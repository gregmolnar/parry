# frozen_string_literal: true

require "test_helper"

module Parry
  class ProtectionTest < ActionDispatch::IntegrationTest
    test "requests pass through when there are no rules" do
      get_as "203.0.113.4"

      assert_response :success
      assert_equal "hello", response.body
    end

    test "a blocklist rule returns 403" do
      create_rule(kind: "blocklist", value: "203.0.113.4")

      get_as "203.0.113.4"
      assert_response :forbidden

      get_as "198.51.100.9"
      assert_response :success
    end

    test "a blocklisted range covers every address in it" do
      create_rule(kind: "blocklist", value: "203.0.113.0/24")

      get_as "203.0.113.200"
      assert_response :forbidden

      get_as "203.0.114.1"
      assert_response :success
    end

    test "a safelist rule wins over a blocklist" do
      create_rule(kind: "blocklist", value: "203.0.113.0/24")
      create_rule(kind: "safelist", value: "203.0.113.7")

      get_as "203.0.113.7"
      assert_response :success

      get_as "203.0.113.8"
      assert_response :forbidden
    end

    test "a throttle returns 429 once the limit is exceeded" do
      create_rule(kind: "throttle", name: "everything", limit: 3, period: 60)

      3.times { get_as "203.0.113.4" }
      assert_response :success

      get_as "203.0.113.4"
      assert_response :too_many_requests

      # Other hosts keep their own counter.
      get_as "198.51.100.9"
      assert_response :success
    end

    test "a throttle only counts the paths it is scoped to" do
      create_rule(kind: "throttle", name: "logins", limit: 2, period: 60, path: "/login")

      3.times { get_as "203.0.113.4", "/" }
      assert_response :success

      2.times { get_as "203.0.113.4", "/login" }
      assert_response :success

      get_as "203.0.113.4", "/login"
      assert_response :too_many_requests
    end

    test "a safelisted host is never throttled" do
      create_rule(kind: "throttle", name: "everything", limit: 1, period: 60)
      create_rule(kind: "safelist", value: "203.0.113.4")

      5.times { get_as "203.0.113.4" }
      assert_response :success
    end

    test "rule changes are picked up without reinstalling the hooks" do
      rule = create_rule(kind: "blocklist", value: "203.0.113.4")

      get_as "203.0.113.4"
      assert_response :forbidden

      # Delete the rule the way another process would: store only, no local sync.
      Parry.store.delete(rule.id)

      get_as "203.0.113.4"
      assert_response :success
    end

    test "a throttle added by another process starts applying" do
      Parry.store.save(Rule.new(kind: "throttle", name: "everything", limit: 1, period: 60))

      get_as "203.0.113.4"
      assert_response :success

      get_as "203.0.113.4"
      assert_response :too_many_requests
    end

    test "a honeypot blocks the host for every later request" do
      create_rule(kind: "honeypot", path: "/.env", name: "Env probe")

      get_as "203.0.113.4", "/"
      assert_response :success

      get_as "203.0.113.4", "/.env"
      assert_response :forbidden

      # The host is now blocked everywhere, not just on the honeypot path.
      get_as "203.0.113.4", "/"
      assert_response :forbidden

      # Everyone else is unaffected.
      get_as "198.51.100.9", "/"
      assert_response :success
    end

    test "a honeypot can catch hosts with a regex" do
      create_rule(kind: "honeypot", path_match: "regex", path: "\\.(env|git)", name: "Config probe")

      get_as "203.0.113.4", "/"
      assert_response :success

      get_as "203.0.113.4", "/.git/config"
      assert_response :forbidden

      # Caught, so blocked everywhere from now on.
      get_as "203.0.113.4", "/"
      assert_response :forbidden

      get_as "198.51.100.9", "/.env"
      assert_response :forbidden

      get_as "192.0.2.7", "/environment"
      assert_response :success
    end

    test "a regex honeypot records the rule that caught the host" do
      create_rule(kind: "honeypot", path_match: "regex", path: "\\.env\\z", name: "Env probe")

      get_as "203.0.113.4", "/config/.env"
      assert_response :forbidden

      caught = Parry.honeypots.find("203.0.113.4")
      assert_equal "/config/.env", caught.path
      assert_equal "Env probe", caught.rule
    end

    test "an unanchored regex honeypot leaves unrelated paths alone" do
      create_rule(kind: "honeypot", path_match: "regex", path: "\\Awp-", name: "Bad anchor")

      # \A anchors at the start of the path, which always begins with /.
      get_as "203.0.113.4", "/wp-login.php"
      assert_response :success
    end

    test "a honeypot matches every path under its prefix" do
      create_rule(kind: "honeypot", path: "/login")

      get_as "203.0.113.4", "/login"
      assert_response :forbidden

      assert Parry.honeypots.caught?("203.0.113.4")
    end

    test "a safelisted host is never caught" do
      create_rule(kind: "honeypot", path: "/.env")
      create_rule(kind: "safelist", value: "203.0.113.4")

      get_as "203.0.113.4", "/.env"
      assert_response :success

      refute Parry.honeypots.caught?("203.0.113.4")
    end

    test "a caught host is recorded with the rule that caught it" do
      create_rule(kind: "honeypot", path: "/.env", name: "Env probe")

      get_as "203.0.113.4", "/.env"

      host = Parry.tracker.find("203.0.113.4")
      assert_equal "Honeypot: Env probe", host.rule
      assert_equal "/.env", host.path
      assert_equal "blocklist", host.match_type

      caught = Parry.honeypots.find("203.0.113.4")
      assert_equal "/.env", caught.path
      assert_equal "Env probe", caught.rule
    end

    test "hammering the honeypot path only records the host once" do
      create_rule(kind: "honeypot", path: "/.env")

      get_as "203.0.113.4", "/.env"
      version = Parry.store.version

      5.times { get_as "203.0.113.4", "/.env" }

      assert_response :forbidden
      assert_equal version, Parry.store.version
      assert_equal 1, Parry.honeypots.count
    end

    test "a host caught by another process is blocked here too" do
      rule = create_rule(kind: "honeypot", path: "/.env")
      Parry.honeypots.record("203.0.113.4", rule: rule, path: "/.env")

      get_as "203.0.113.4", "/"
      assert_response :forbidden
    end

    test "unblocking releases a caught host" do
      create_rule(kind: "honeypot", path: "/.env", name: "Env probe")

      get_as "203.0.113.4", "/.env"
      assert_response :forbidden

      Parry.unblock("203.0.113.4")

      refute Parry.honeypots.caught?("203.0.113.4")

      get_as "203.0.113.4", "/"
      assert_response :success

      # The honeypot itself stays in place and can catch the host again.
      get_as "203.0.113.4", "/.env"
      assert_response :forbidden
    end

    test "deleting a honeypot rule leaves the hosts it caught blocked" do
      rule = create_rule(kind: "honeypot", path: "/.env")

      get_as "203.0.113.4", "/.env"
      assert_response :forbidden

      Parry.store.delete(rule.id)

      get_as "203.0.113.4", "/"
      assert_response :forbidden

      get_as "198.51.100.9", "/.env"
      assert_response :success
    end

    test "blocked and throttled requests are recorded" do
      create_rule(kind: "blocklist", value: "203.0.113.4")
      create_rule(kind: "throttle", name: "everything", limit: 1, period: 60)

      get_as "203.0.113.4"
      2.times { get_as "198.51.100.9" }

      hosts = Parry.tracker.all.index_by(&:ip)

      assert_equal 1, hosts["203.0.113.4"].hits
      assert_equal "blocklist", hosts["203.0.113.4"].match_type
      assert_equal "Blocklist: 203.0.113.4", hosts["203.0.113.4"].rule

      assert_equal 1, hosts["198.51.100.9"].hits
      assert_equal "throttle", hosts["198.51.100.9"].match_type
      assert_equal "Throttle: everything", hosts["198.51.100.9"].rule
      assert_equal "/", hosts["198.51.100.9"].path
    end

    test "successful requests are not recorded" do
      get_as "203.0.113.4"

      assert_empty Parry.tracker.all
    end

    test "unblocking removes the blocklist rules covering the address" do
      create_rule(kind: "blocklist", value: "203.0.113.0/24")
      create_rule(kind: "blocklist", value: "203.0.113.7")

      get_as "203.0.113.7"
      assert_response :forbidden

      removed = Parry.unblock("203.0.113.7")

      assert_equal 2, removed.size
      assert_empty Parry.store.all
      assert_empty Parry.tracker.all

      get_as "203.0.113.7"
      assert_response :success
    end

    test "unblocking resets throttle counters" do
      create_rule(kind: "throttle", name: "everything", limit: 2, period: 60)

      3.times { get_as "203.0.113.4" }
      assert_response :too_many_requests

      Parry.unblock("203.0.113.4")

      get_as "203.0.113.4"
      assert_response :success
    end

    test "unblocking leaves other hosts alone" do
      create_rule(kind: "blocklist", value: "203.0.113.4")
      create_rule(kind: "blocklist", value: "198.51.100.9")

      Parry.unblock("203.0.113.4")

      get_as "198.51.100.9"
      assert_response :forbidden
    end
  end
end
