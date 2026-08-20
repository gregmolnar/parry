# frozen_string_literal: true

require "redis"

module Parry
  # Runtime configuration for the engine.
  #
  #   Parry.configure do |config|
  #     config.redis = Redis.new(url: ENV["PARRY_REDIS_URL"])
  #     config.max_tracked_hosts = 5_000
  #   end
  class Configuration
    attr_writer :redis

    # URL used to build the default Redis client. Ignored when +redis+ is set.
    attr_accessor :redis_url

    # Prefix for every Redis key Parry writes.
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
      @redis_url = ENV["PARRY_REDIS_URL"] || ENV["REDIS_URL"]
      @key_prefix = "parry"
      @auto_install = true
      @track_events = true
      @max_tracked_hosts = 1000
      @regex_timeout = 0.05
    end

    # A Redis client, or anything responding to +with+ (such as a
    # ConnectionPool) that yields one.
    def redis
      @redis ||= redis_url ? Redis.new(url: redis_url) : Redis.new
    end
  end
end
