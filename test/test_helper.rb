# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

ENV["RAILS_ENV"] = "test"

# PARRY_TEST_BACKEND picks the storage backend the suite runs against: sqlite
# (default), postgres, mysql or redis. See test/dummy/config/parry_backend.rb,
# which also refuses to wipe anything that is not a local server.
if ENV.fetch("PARRY_TEST_BACKEND", "sqlite") == "redis"
  # This suite calls FLUSHDB before every single test, so it must never inherit
  # an ambient REDIS_URL - that would wipe whatever the surrounding shell, CI job
  # or deploy environment happens to point at. Override with PARRY_TEST_REDIS_URL.
  ENV["REDIS_URL"] = ENV.fetch("PARRY_TEST_REDIS_URL", "redis://127.0.0.1:6380/1")
end

require_relative "dummy/config/environment"
require "rails/test_help"
require "tempfile"
require "minitest/mock"

ActionController::Base.allow_forgery_protection = false

module Parry
  module TestHelpers
    def setup
      super
      ParryTestBackend.clear!
      Parry.reset!
      Rack::Attack.cache.store.clear
      # The hooks are registered once per process; drop the memoized snapshot so
      # each test starts from an empty rule set.
      Parry.adapter.sync!(force: true)
    end

    # Requests are only recorded through ActiveSupport::Notifications, which are
    # delivered synchronously, but the writes happen in the same request.
    def get_as(ip, path = "/", **options)
      get path, **options, headers: {"REMOTE_ADDR" => ip}.merge(options[:headers] || {})
    end

    def create_rule(attributes)
      rule = Parry::Rule.new(attributes)
      assert Parry.store.save(rule), -> { "expected rule to save: #{rule.errors.full_messages.join(", ")}" }
      Parry.adapter.sync!(force: true)
      rule
    end

    def redis_backend?
      ParryTestBackend.redis?
    end

    def active_record_backend?
      ParryTestBackend.active_record?
    end
  end
end

puts "Parry test backend: #{ParryTestBackend.name}"

class ActiveSupport::TestCase
  include Parry::TestHelpers
end
