# frozen_string_literal: true

module Parry
  # Runtime configuration for the engine.
  #
  #   Parry.configure do |config|
  #     config.backend = :active_record
  #     config.max_tracked_hosts = 5_000
  #   end
  class Configuration
    BACKENDS = %i[active_record redis].freeze

    # Where rules, caught hosts and blocked hosts are stored: :active_record
    # (the default, tables created by `rails generate parry:install`) or :redis.
    attr_reader :backend

    # ActiveRecord backend: options passed to +connects_to+ on
    # Parry::ApplicationRecord, to keep Parry's tables in a database of their
    # own. For example {database: {writing: :parry}}. Default: nil, which uses
    # the application's primary database.
    attr_accessor :connects_to

    # ActiveRecord backend: how long, in seconds, a process trusts the rules
    # version it last read before asking the database again. Writes made by the
    # process itself are seen at once; writes made elsewhere within this long.
    # 0 checks on every request. Default: 2.
    attr_accessor :version_cache_ttl

    # ActiveRecord backend: trim the blocked hosts table to max_tracked_hosts
    # after this many records... Default: 1000.
    attr_accessor :tracker_trim_every

    # ...or once this many seconds have passed since the last trim, whichever
    # comes first. nil disables the time-based trigger. Default: 60. With both
    # unset (nil/0 and nil) the table is trimmed on every record.
    attr_accessor :tracker_trim_interval

    # ActiveRecord backend: write a given address to the blocked hosts table at
    # most once per this many seconds. Hits in between are counted in memory
    # and added by the next write. nil or 0 writes every hit. Default: nil.
    attr_accessor :tracker_write_interval

    attr_writer :redis

    # Redis backend: URL used to build the default Redis client. Ignored when
    # +redis+ is set.
    attr_accessor :redis_url

    # Redis backend: prefix for every Redis key Parry writes.
    attr_accessor :key_prefix

    # Register the Rack::Attack hooks automatically when the engine boots.
    attr_accessor :auto_install

    # Record blocked/throttled requests so they show up under "Blocked hosts".
    attr_accessor :track_events

    # Maximum number of hosts kept in the blocked hosts list.
    attr_accessor :max_tracked_hosts

    # How long a honeypot regex may spend on one path before it is abandoned.
    # Guards against a pattern that backtracks catastrophically.
    attr_accessor :regex_timeout

    def initialize
      @backend = :active_record
      @connects_to = nil
      @version_cache_ttl = 2
      @tracker_trim_every = 1000
      @tracker_trim_interval = 60
      @tracker_write_interval = nil
      @redis_url = ENV["PARRY_REDIS_URL"] || ENV["REDIS_URL"]
      @key_prefix = "parry"
      @auto_install = true
      @track_events = true
      @max_tracked_hosts = 1000
      @regex_timeout = 0.05
    end

    def backend=(name)
      name = name.to_s.to_sym
      unless BACKENDS.include?(name)
        raise Parry::Error, "Unknown Parry backend #{name.inspect}. Use one of: #{BACKENDS.map(&:inspect).join(", ")}."
      end

      @backend = name
    end

    # A Redis client, or anything responding to +with+ (such as a
    # ConnectionPool) that yields one. Only used by the Redis backend.
    def redis
      @redis ||= begin
        Backends::Redis.require_client!
        redis_url ? ::Redis.new(url: redis_url) : ::Redis.new
      end
    end
  end
end
