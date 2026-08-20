# frozen_string_literal: true

require "logger"
require "active_support"
require "active_support/core_ext/object/blank"
require "active_support/core_ext/hash/keys"
require "active_support/core_ext/hash/slice"
require "rack/attack"

require_relative "parry/version"
require_relative "parry/configuration"
require_relative "parry/rule"
require_relative "parry/rule_set"
require_relative "parry/rule_store"
require_relative "parry/rule_transfer"
require_relative "parry/blocked_host"
require_relative "parry/caught_host"
require_relative "parry/honeypot_store"
require_relative "parry/tracker"
require_relative "parry/rack_attack_adapter"

module Parry
  class Error < StandardError; end

  class << self
    attr_writer :logger

    def config
      @config ||= Configuration.new
    end
    alias_method :configuration, :config

    def configure
      yield config
    end

    def with_redis(&block)
      client = config.redis
      client.respond_to?(:with) ? client.with(&block) : yield(client)
    end

    def store
      @store ||= RuleStore.new
    end

    def tracker
      @tracker ||= Tracker.new
    end

    def honeypots
      @honeypots ||= HoneypotStore.new
    end

    def adapter
      @adapter ||= RackAttackAdapter.new
    end

    def install!
      adapter.install!
    end

    def rules
      store.all
    end

    def unblock(ip)
      adapter.unblock(ip)
    end

    def blocked_hosts(limit: 100)
      tracker.all(limit: limit)
    end

    def logger
      @logger ||= if defined?(::Rails) && ::Rails.respond_to?(:logger) && ::Rails.logger
        ::Rails.logger
      else
        ::Logger.new($stderr)
      end
    end

    def reset!
      @store = nil
      @tracker = nil
      @honeypots = nil
      adapter.reset!
    end
  end
end

require_relative "parry/engine" if defined?(::Rails)
