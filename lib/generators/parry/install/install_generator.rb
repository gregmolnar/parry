# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module Parry
  module Generators
    # rails generate parry:install [--database=parry]
    #
    # Writes the migration for the ActiveRecord backend's tables and, unless one
    # exists, a commented initializer.
    class InstallGenerator < ::Rails::Generators::Base
      include ::ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      class_option :database, type: :string, aliases: %i[--db],
        desc: "The database whose migrations_paths the migration goes to (see config.connects_to)"

      desc "Creates the migration for Parry's tables and a config/initializers/parry.rb"

      def create_migration_file
        migration_template "create_parry_tables.rb.erb",
          File.join(db_migrate_path, "create_parry_tables.rb"),
          migration_version: migration_version
      end

      def create_initializer
        template "initializer.rb", "config/initializers/parry.rb", skip: true
      end

      private

      def migration_version
        "[#{::ActiveRecord::VERSION::STRING.to_f}]"
      end
    end
  end
end
