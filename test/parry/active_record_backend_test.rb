# frozen_string_literal: true

require "test_helper"
require "parry/backends/active_record"

module Parry
  # The parts of the ActiveRecord backend the Redis backend has no equivalent
  # for: the version cache and the throttled tracker writes.
  class ActiveRecordBackendTest < ActiveSupport::TestCase
    # A method rather than a setup block: it has to run after the shared setup,
    # which resets Parry.
    def setup
      super
      skip "ActiveRecord backend only" unless active_record_backend?

      @saved_config = %i[version_cache_ttl tracker_trim_every tracker_trim_interval tracker_write_interval
        max_tracked_hosts].to_h { |name| [name, Parry.config.public_send(name)] }
      @time = 1000.0
      @backend = Backends::ActiveRecord.new(clock: -> { @time })
      Parry.instance_variable_set(:@backend, @backend)
      Parry.instance_variable_set(:@backend_name, :active_record)
    end

    teardown do
      @saved_config&.each { |name, value| Parry.config.public_send(:"#{name}=", value) }
      Parry.reset!
    end

    def bump_elsewhere
      Records::Version.where(id: Backends::ActiveRecord::VERSION_ROW_ID).update_all("version = version + 1")
    end

    def queries
      count = 0
      callback = ->(*, payload) { count += 1 unless %w[SCHEMA TRANSACTION].include?(payload[:name]) }
      ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { yield }
      count
    end

    # Version cache

    test "the version is read once per TTL" do
      Parry.config.version_cache_ttl = 10
      @backend.bump_version
      seen = @backend.version

      bump_elsewhere

      assert_equal 0, queries { 5.times { assert_equal seen, @backend.version } }

      @time += 10
      assert_equal seen + 1, @backend.version
    end

    test "a write made by this process is seen at once" do
      Parry.config.version_cache_ttl = 60
      before = @backend.version

      Parry.store.save(Rule.new(kind: "blocklist", value: "203.0.113.4"))

      assert_equal before + 1, @backend.version
    end

    test "a TTL of zero reads the version every time" do
      Parry.config.version_cache_ttl = 0
      @backend.bump_version
      before = @backend.version

      bump_elsewhere

      assert_equal before + 1, @backend.version
    end

    test "sync! does not query while the version is cached" do
      Parry.config.version_cache_ttl = 60
      create_rule(kind: "blocklist", value: "203.0.113.4")
      Parry.adapter.sync!

      assert_equal 0, queries { 5.times { Parry.adapter.sync! } }
    end

    test "a rule written by another process applies once the TTL runs out" do
      Parry.config.version_cache_ttl = 5
      @backend.bump_version
      Parry.adapter.sync!(force: true)

      # Another process: the rule and the version bump land in the database,
      # this process' cache knows nothing about it.
      Records::Rule.insert_all!([{id: "elsewhere", kind: "blocklist", payload: Rule.new(id: "elsewhere",
        kind: "blocklist", value: "203.0.113.4", created_at: 1).to_json, created_at: 1}])
      bump_elsewhere

      Parry.adapter.sync!
      refute Parry.adapter.rule_set.blocklisted?("203.0.113.4")

      @time += 5
      Parry.adapter.sync!
      assert Parry.adapter.rule_set.blocklisted?("203.0.113.4")
    end

    # Trimming

    def record(ip, at: @time)
      @backend.track(ip: ip, match_type: "blocklist", at: Time.at(at.to_i))
    end

    test "the blocked hosts table is trimmed every N records" do
      Parry.config.max_tracked_hosts = 3
      Parry.config.tracker_trim_every = 5
      Parry.config.tracker_trim_interval = nil

      4.times { |index| record("203.0.113.#{index}", at: 1000 + index) }
      assert_equal 4, Parry.tracker.count

      record("203.0.113.4", at: 1004)
      assert_equal %w[203.0.113.4 203.0.113.3 203.0.113.2], Parry.tracker.all.map(&:ip)
    end

    test "the blocked hosts table is trimmed every N seconds" do
      Parry.config.max_tracked_hosts = 2
      Parry.config.tracker_trim_every = nil
      Parry.config.tracker_trim_interval = 30

      5.times { |index| record("203.0.113.#{index}", at: 1000 + index) }
      assert_equal 5, Parry.tracker.count

      @time += 30
      record("203.0.113.5", at: 1005)
      assert_equal %w[203.0.113.5 203.0.113.4], Parry.tracker.all.map(&:ip)

      # Not again until another 30 seconds have passed.
      record("203.0.113.6", at: 1006)
      assert_equal 3, Parry.tracker.count
    end

    test "with both triggers off the table is trimmed on every record" do
      Parry.config.max_tracked_hosts = 2
      Parry.config.tracker_trim_every = nil
      Parry.config.tracker_trim_interval = nil

      3.times { |index| record("203.0.113.#{index}", at: 1000 + index) }

      assert_equal 2, Parry.tracker.count
    end

    test "hosts seen in the same second are trimmed by address, like Redis" do
      Parry.config.max_tracked_hosts = 2
      %w[203.0.113.1 203.0.113.3 203.0.113.2].each { |ip| record(ip, at: 1000) }

      assert_equal 1, @backend.trim_tracked_hosts
      assert_equal %w[203.0.113.3 203.0.113.2], Parry.tracker.all.map(&:ip)
    end

    # Write interval

    test "tracker_write_interval writes a busy address once per interval" do
      Parry.config.tracker_write_interval = 10

      assert record("203.0.113.4")
      2.times { refute record("203.0.113.4") }
      assert_equal 1, Parry.tracker.find("203.0.113.4").hits

      # Other addresses are written straight away.
      assert record("198.51.100.9")

      @time += 10
      assert record("203.0.113.4")
      assert_equal 4, Parry.tracker.find("203.0.113.4").hits
    end

    test "forgetting an address drops the hits held back for it" do
      Parry.config.tracker_write_interval = 10
      record("203.0.113.4")
      refute record("203.0.113.4")

      Parry.tracker.forget("203.0.113.4")

      assert record("203.0.113.4")
      assert_equal 1, Parry.tracker.find("203.0.113.4").hits
    end

    test "without a write interval every hit is written" do
      Parry.config.tracker_write_interval = nil

      3.times { assert record("203.0.113.4") }

      assert_equal 3, Parry.tracker.find("203.0.113.4").hits
    end

    test "recording a hit is a single statement" do
      Parry.config.tracker_trim_every = 1000
      Parry.config.tracker_trim_interval = nil
      record("203.0.113.4")

      assert_equal 1, queries { record("203.0.113.4") }
    end

    # Caught hosts

    test "catching the same host from two places stores it once" do
      host = CaughtHost.new(ip: "203.0.113.4", path: "/.env", caught_at: 1000)

      assert @backend.add_caught_host(host)
      refute @backend.add_caught_host(CaughtHost.new(ip: "203.0.113.4", path: "/other", caught_at: 2000))
      assert_equal "/.env", @backend.caught_host("203.0.113.4").path
    end

    # Connection

    test "Parry's tables can live in a database of their own" do
      skip "only the SQLite run uses a separate database" unless ParryTestBackend.separate_database?

      assert_equal "parry", ApplicationRecord.connection_db_config.name
      ActiveRecord::Base.connection_pool.with_connection do |connection|
        refute connection.table_exists?("parry_rules")
      end
      ApplicationRecord.connection_pool.with_connection do |connection|
        assert connection.table_exists?("parry_rules")
      end
    end
  end
end
