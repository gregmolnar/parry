# frozen_string_literal: true

# Points the dummy application at one of Parry's storage backends, picked with
# PARRY_TEST_BACKEND:
#
#   sqlite    ActiveRecord on SQLite (default). Parry's tables live in a
#             database of their own through config.connects_to, so the
#             separate-database setup is exercised too.
#   postgres  ActiveRecord on PostgreSQL, sharing the primary connection.
#   mysql     ActiveRecord on MySQL, sharing the primary connection.
#   redis     The Redis backend.
#
# For the ActiveRecord backends the tables are created from the migration that
# `rails generate parry:install` writes, so that migration is tested as well.

require "erb"
require "fileutils"
require "uri"

module ParryTestBackend
  ROOT = File.expand_path("../../..", __dir__)
  MIGRATION_TEMPLATE = File.join(ROOT, "lib/generators/parry/install/templates/create_parry_tables.rb.erb")
  TABLES = %w[parry_rules parry_versions parry_blocked_hosts parry_caught_hosts].freeze

  DATABASE_URLS = {
    "postgres" => -> { ENV.fetch("PARRY_TEST_POSTGRES_URL", "postgres://parry:parry@127.0.0.1:5433/parry_test") },
    "mysql" => -> { ENV.fetch("PARRY_TEST_MYSQL_URL", "trilogy://root:parry@127.0.0.1:3307/parry_test") }
  }.freeze

  class << self
    def name
      ENV.fetch("PARRY_TEST_BACKEND", "sqlite")
    end

    def redis?
      name == "redis"
    end

    def active_record?
      !redis?
    end

    def separate_database?
      name == "sqlite"
    end

    def database_url
      DATABASE_URLS.fetch(name).call
    end

    def configure!
      case name
      when "redis"
        refuse_remote!(ENV.fetch("REDIS_URL"), "PARRY_TEST_REDIS_URL", "PARRY_ALLOW_REMOTE_TEST_REDIS")
        Parry.config.backend = :redis
        Rack::Attack.cache.store = ActiveSupport::Cache::RedisCacheStore.new(url: ENV.fetch("REDIS_URL"))
      when "sqlite", "postgres", "mysql"
        Parry.config.backend = :active_record
        # Rack::Attack only needs an incrementable cache store; nothing about
        # it requires Redis.
        Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
        connect!
        create_tables!
      else
        abort "Unknown PARRY_TEST_BACKEND #{name.inspect}: use sqlite, postgres, mysql or redis."
      end
    end

    def connect!
      require "active_record"
      ActiveRecord::Migration.verbose = false

      if separate_database?
        dir = File.join(ROOT, "tmp")
        FileUtils.mkdir_p(dir)
        primary = File.join(dir, "test-primary.sqlite3")
        parry = File.join(dir, "test-parry.sqlite3")
        [primary, parry].each { |path| FileUtils.rm_f([path, "#{path}-wal", "#{path}-shm"]) }

        ActiveRecord::Base.configurations = {
          ActiveRecord::ConnectionHandling::DEFAULT_ENV.call => {
            "primary" => {"adapter" => "sqlite3", "database" => primary},
            "parry" => {"adapter" => "sqlite3", "database" => parry}
          }
        }
        ActiveRecord::Base.establish_connection(:primary)
        Parry.config.connects_to = {database: {writing: :parry}}
      else
        variable = "PARRY_TEST_#{name.upcase}_URL"
        refuse_remote!(database_url, variable, "PARRY_ALLOW_REMOTE_TEST_DATABASE")
        ActiveRecord::Base.establish_connection(database_url)
      end
    end

    # Every test wipes Parry's data, so only local servers are accepted.
    def refuse_remote!(url, variable, flag)
      host = URI.parse(url).host
      return if %w[127.0.0.1 localhost ::1].include?(host) || ENV[flag]

      abort <<~MESSAGE
        Refusing to run against #{url}.
        Every test wipes Parry's data there. Point #{variable} at a local
        server, or set #{flag}=1 if you really mean it.
      MESSAGE
    rescue URI::InvalidURIError
      abort "#{variable} is not a valid URL: #{url.inspect}"
    end

    # Runs the generator's migration against Parry's connection.
    def create_tables!
      require "parry/application_record"

      Parry::ApplicationRecord.apply_connection_config!
      connection_pool = Parry::ApplicationRecord.connection_pool
      connection_pool.with_connection do |connection|
        TABLES.each { |table| connection.drop_table(table, if_exists: true) }
        migration_class.new.exec_migration(connection, :up)
      end
    end

    def migration_class
      return CreateParryTables if defined?(::CreateParryTables)

      source = ERB.new(File.read(MIGRATION_TEMPLATE))
        .result_with_hash(migration_version: "[#{ActiveRecord::VERSION::STRING.to_f}]")
      Object.class_eval(source, MIGRATION_TEMPLATE)
      ::CreateParryTables
    end

    # Empties Parry's storage between tests.
    def clear!
      if redis?
        Parry.with_redis(&:flushdb)
      else
        Parry::ApplicationRecord.connection_pool.with_connection do |connection|
          TABLES.each { |table| connection.execute("DELETE FROM #{connection.quote_table_name(table)}") }
        end
      end
    end
  end
end

ParryTestBackend.configure!
