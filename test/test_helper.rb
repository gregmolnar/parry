# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

ENV["RAILS_ENV"] = "test"

# This suite calls FLUSHDB before every single test, so it must never inherit an
# ambient REDIS_URL - that would wipe whatever the surrounding shell, CI job or
# deploy environment happens to point at. Override with PARRY_TEST_REDIS_URL.
ENV["REDIS_URL"] = ENV.fetch("PARRY_TEST_REDIS_URL", "redis://127.0.0.1:6380/1")

require "uri"

# Second belt: refuse to flush anything that is not a local Redis.
begin
  host = URI.parse(ENV["REDIS_URL"]).host
  unless %w[127.0.0.1 localhost ::1].include?(host) || ENV["PARRY_ALLOW_REMOTE_TEST_REDIS"]
    abort <<~MESSAGE
      Refusing to run the test suite against #{ENV["REDIS_URL"]}.
      Every test flushes this database. Point PARRY_TEST_REDIS_URL at a local
      Redis, or set PARRY_ALLOW_REMOTE_TEST_REDIS=1 if you really mean it.
    MESSAGE
  end
rescue URI::InvalidURIError
  abort "PARRY_TEST_REDIS_URL is not a valid URL: #{ENV["REDIS_URL"].inspect}"
end

require_relative "dummy/config/environment"
require "rails/test_help"
require "tempfile"

ActionController::Base.allow_forgery_protection = false

module Parry
  module TestHelpers
    def setup
      super
      Parry.with_redis(&:flushdb)
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
  end
end

class ActiveSupport::TestCase
  include Parry::TestHelpers
end
