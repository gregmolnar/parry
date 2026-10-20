# frozen_string_literal: true

require "test_helper"

module Parry
  class ConfigurationTest < ActiveSupport::TestCase
    test "ActiveRecord is the default backend" do
      assert_equal :active_record, Configuration.new.backend
    end

    test "the backend can be given as a string or a symbol" do
      config = Configuration.new
      config.backend = "redis"
      assert_equal :redis, config.backend
    end

    test "an unknown backend is refused" do
      error = assert_raises(Parry::Error) { Configuration.new.backend = :mongo }
      assert_match(/Unknown Parry backend :mongo/, error.message)
    end

    test "the defaults of the ActiveRecord options" do
      config = Configuration.new

      assert_nil config.connects_to
      assert_equal 2, config.version_cache_ttl
      assert_equal 1000, config.tracker_trim_every
      assert_equal 60, config.tracker_trim_interval
      assert_nil config.tracker_write_interval
    end

    test "the Redis backend explains a missing redis gem" do
      no_redis = ->(*) { raise LoadError, "cannot load such file -- redis" }

      Backends::Redis.stub(:require, no_redis) do
        error = assert_raises(Parry::Error) { Backends::Redis.new }
        assert_match(/needs the redis gem/, error.message)
        assert_match(/gem "redis"/, error.message)
      end
    end

    test "the backend follows the configuration" do
      expected = redis_backend? ? Backends::Redis : Backends::ActiveRecord
      assert_kind_of expected, Parry.backend
    end
  end
end
