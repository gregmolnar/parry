# frozen_string_literal: true

require "test_helper"

module Parry
  # Runs against every backend.
  class TrackerTest < ActiveSupport::TestCase
    test "recording a host counts its hits and keeps when it was first seen" do
      Parry.tracker.record(ip: "203.0.113.4", match_type: "blocklist", rule: "Blocklist: a", path: "/a", at: Time.at(1000))
      Parry.tracker.record(ip: "203.0.113.4", match_type: "throttle", rule: "Throttle: b", path: "/b", at: Time.at(2000))

      host = Parry.tracker.find("203.0.113.4")
      assert_equal 2, host.hits
      assert_equal "throttle", host.match_type
      assert_equal "Throttle: b", host.rule
      assert_equal "/b", host.path
      assert_equal Time.at(1000), host.first_seen
      assert_equal Time.at(2000), host.last_seen
    end

    test "a record without a rule or path keeps the ones already stored" do
      Parry.tracker.record(ip: "203.0.113.4", match_type: "blocklist", rule: "Blocklist: a", path: "/a", at: Time.at(1000))
      Parry.tracker.record(ip: "203.0.113.4", match_type: "blocklist", at: Time.at(2000))

      host = Parry.tracker.find("203.0.113.4")
      assert_equal "Blocklist: a", host.rule
      assert_equal "/a", host.path
    end

    test "all lists the most recent first" do
      Parry.tracker.record(ip: "203.0.113.1", match_type: "blocklist", at: Time.at(1000))
      Parry.tracker.record(ip: "203.0.113.2", match_type: "blocklist", at: Time.at(3000))
      Parry.tracker.record(ip: "203.0.113.3", match_type: "blocklist", at: Time.at(2000))

      assert_equal %w[203.0.113.2 203.0.113.3 203.0.113.1], Parry.tracker.all.map(&:ip)
      assert_equal %w[203.0.113.2], Parry.tracker.all(limit: 1).map(&:ip)
      assert_equal 3, Parry.tracker.count
    end

    test "trimming keeps the most recent hosts" do
      Parry.config.max_tracked_hosts = 2
      4.times { |index| Parry.tracker.record(ip: "203.0.113.#{index}", match_type: "blocklist", at: Time.at(1000 + index)) }

      Parry.tracker.trim!

      assert_equal %w[203.0.113.3 203.0.113.2], Parry.tracker.all.map(&:ip)
    ensure
      Parry.config.max_tracked_hosts = 1000
    end

    test "forget and clear" do
      Parry.tracker.record(ip: "203.0.113.1", match_type: "blocklist")
      Parry.tracker.record(ip: "203.0.113.2", match_type: "blocklist")

      Parry.tracker.forget("203.0.113.1")
      assert_nil Parry.tracker.find("203.0.113.1")
      assert_equal 1, Parry.tracker.count

      Parry.tracker.clear
      assert_equal 0, Parry.tracker.count
    end

    test "a blank address is ignored" do
      Parry.tracker.record(ip: nil, match_type: "blocklist")
      Parry.tracker.record(ip: "", match_type: "blocklist")

      assert_equal 0, Parry.tracker.count
    end

    test "a tracker failure does not break the request" do
      create_rule(kind: "blocklist", value: "203.0.113.4")
      failing = Object.new
      def failing.record(**) = raise("storage is down")

      Parry.stub(:tracker, failing) do
        Parry.adapter.handle_event("blocklist", Rack::Attack::Request.new(Rack::MockRequest.env_for("/", "REMOTE_ADDR" => "203.0.113.4")))
      end
    end
  end
end
