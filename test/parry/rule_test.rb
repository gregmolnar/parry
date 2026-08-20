# frozen_string_literal: true

require "test_helper"

module Parry
  class RuleTest < ActiveSupport::TestCase
    test "a blocklist rule needs a valid IP or range" do
      assert Rule.new(kind: "blocklist", value: "203.0.113.4").valid?
      assert Rule.new(kind: "blocklist", value: "203.0.113.0/24").valid?
      assert Rule.new(kind: "safelist", value: "2001:db8::/32").valid?

      rule = Rule.new(kind: "blocklist", value: "not-an-ip")
      refute rule.valid?
      assert_includes rule.errors.full_messages.to_sentence, "not a valid IP address"

      rule = Rule.new(kind: "blocklist", value: "")
      refute rule.valid?
    end

    test "a new rule is a honeypot by default" do
      assert_equal "honeypot", Rule.new.kind
      assert_equal "honeypot", Rule::KINDS.first
    end

    test "an unknown kind is rejected" do
      rule = Rule.new(kind: "allowlist", value: "203.0.113.4")
      refute rule.valid?
      assert_includes rule.errors.full_messages.to_sentence, "not a valid rule type"
    end

    test "a throttle needs a name, a limit and a period" do
      rule = Rule.new(kind: "throttle")
      refute rule.valid?
      assert_equal ["Name can't be blank", "Limit is not a number", "Period is not a number"],
        rule.errors.full_messages

      refute Rule.new(kind: "throttle", name: "logins", limit: 0, period: 60).valid?
      refute Rule.new(kind: "throttle", name: "logins", limit: 5, period: -1).valid?
      assert Rule.new(kind: "throttle", name: "logins", limit: 5, period: 60).valid?
    end

    test "throttle names have to be unique" do
      create_rule(kind: "throttle", name: "logins", limit: 5, period: 60)

      duplicate = Rule.new(kind: "throttle", name: "logins", limit: 10, period: 60)
      refute Parry.store.save(duplicate)
      assert_includes duplicate.errors.full_messages.to_sentence, "already used by another throttle"
    end

    test "a throttle can keep its own name when updated" do
      rule = create_rule(kind: "throttle", name: "logins", limit: 5, period: 60)

      rule.limit = 25
      assert Parry.store.save(rule)
      assert_equal 25, Parry.store.find(rule.id).limit
    end

    test "a honeypot needs a path prefix" do
      rule = Rule.new(kind: "honeypot")
      refute rule.valid?
      assert_includes rule.errors.full_messages.to_sentence, "Path can't be blank"

      rule = Rule.new(kind: "honeypot", path: "wp-login.php")
      refute rule.valid?
      assert_includes rule.errors.full_messages.to_sentence, "has to start with /"

      assert Rule.new(kind: "honeypot", path: "/wp-login.php").valid?
    end

    test "matches_path? only matches under the prefix" do
      rule = Rule.new(kind: "honeypot", path: "/wp-login.php")

      assert rule.matches_path?("/wp-login.php")
      assert rule.matches_path?("/wp-login.php.bak")
      refute rule.matches_path?("/login")
      refute rule.matches_path?(nil)

      # A blank prefix must never match, or a honeypot would catch the whole site.
      refute Rule.new(kind: "honeypot").matches_path?("/anything")
    end

    test "a honeypot can match by regex" do
      rule = Rule.new(kind: "honeypot", path_match: "regex", path: "\\.(env|git)")
      assert rule.valid?

      assert rule.matches_path?("/.env")
      assert rule.matches_path?("/.git/config")
      assert rule.matches_path?("/nested/.env")
      refute rule.matches_path?("/environment")
      refute rule.matches_path?("/")
      refute rule.matches_path?(nil)
    end

    test "a regex honeypot does not have to start with a slash" do
      assert Rule.new(kind: "honeypot", path_match: "regex", path: "\\.env\\z").valid?
      refute Rule.new(kind: "honeypot", path_match: "prefix", path: "\\.env").valid?
    end

    test "an unparseable regex is rejected" do
      rule = Rule.new(kind: "honeypot", path_match: "regex", path: "wp-(login")

      refute rule.valid?
      assert_includes rule.errors.full_messages.to_sentence, "not a valid regular expression"
    end

    test "an unknown way of matching a path is rejected" do
      rule = Rule.new(kind: "honeypot", path_match: "glob", path: "/.env")

      refute rule.valid?
      assert_includes rule.errors.full_messages.to_sentence, "not a valid way to match a path"
    end

    test "a regex is anchored only where the author anchors it" do
      anchored = Rule.new(kind: "honeypot", path_match: "regex", path: "\\A/admin\\z")

      assert anchored.matches_path?("/admin")
      refute anchored.matches_path?("/admin/users")
      refute anchored.matches_path?("/x/admin")
    end

    test "a regex that backtracks catastrophically gives up instead of hanging" do
      # A backreference defeats the memoisation that makes Ruby shrug off most
      # of the textbook ReDoS patterns, so this one really does run away.
      rule = Rule.new(kind: "honeypot", path_match: "regex", path: "(a+)+\\1b$")
      candidate = "/" + ("a" * 40) + "!"

      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      refute rule.matches_path?(candidate)
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

      # It gave up at the configured timeout rather than running forever.
      assert_operator elapsed, :>=, Parry.config.regex_timeout
      assert_operator elapsed, :<, 2.0
    end

    test "only honeypots match by regex" do
      throttle = Rule.new(kind: "throttle", name: "api", limit: 5, period: 60,
        path_match: "regex", path: "\\.env")

      refute throttle.regex_match?
      refute throttle.matches_path?("/.env")
      assert throttle.matches_path?("\\.env/x")
    end

    test "a honeypot labels itself with its path when it has no name" do
      assert_equal "/.env", Rule.new(kind: "honeypot", path: "/.env").label
      assert_equal "Env probe", Rule.new(kind: "honeypot", path: "/.env", name: "Env probe").label
    end

    test "matches_ip? covers single addresses and ranges" do
      assert Rule.new(kind: "blocklist", value: "203.0.113.4").matches_ip?("203.0.113.4")
      refute Rule.new(kind: "blocklist", value: "203.0.113.4").matches_ip?("203.0.113.5")

      range = Rule.new(kind: "blocklist", value: "203.0.113.0/24")
      assert range.matches_ip?("203.0.113.99")
      refute range.matches_ip?("198.51.100.1")

      refute range.matches_ip?(nil)
      refute range.matches_ip?("")
      refute range.matches_ip?("garbage")
      refute Rule.new(kind: "throttle", name: "x", limit: 1, period: 1).matches_ip?("203.0.113.4")
    end

    test "normalize! drops the attributes that do not apply" do
      rule = Rule.new(kind: "blocklist", value: " 203.0.113.4 ", limit: 5, period: 60, path: "/login")
      rule.normalize!

      assert_equal "203.0.113.4", rule.value
      assert_nil rule.limit
      assert_nil rule.period
      assert_nil rule.path

      throttle = Rule.new(kind: "throttle", name: "logins", value: "203.0.113.4", limit: 5, period: 60)
      throttle.normalize!
      assert_nil throttle.value

      honeypot = Rule.new(kind: "honeypot", path: " /.env ", value: "203.0.113.4", limit: 5, period: 60)
      honeypot.normalize!
      assert_equal "/.env", honeypot.path
      assert_nil honeypot.value
      assert_nil honeypot.limit
      assert_nil honeypot.period

      # A throttle keeps its path but is always a prefix match.
      throttle = Rule.new(kind: "throttle", name: "api", limit: 5, period: 60, path: "/api", path_match: "regex")
      throttle.normalize!
      assert_equal "/api", throttle.path
      assert_equal "prefix", throttle.path_match

      blocked = Rule.new(kind: "blocklist", value: "203.0.113.4", path: "/x", path_match: "regex")
      blocked.normalize!
      assert_nil blocked.path
      assert_equal "prefix", blocked.path_match

      # Switching a honeypot from regex to prefix drops the compiled pattern.
      switching = Rule.new(kind: "honeypot", path_match: "regex", path: "\\.env")
      assert switching.matches_path?("/.env")
      switching.path_match = "prefix"
      switching.path = "/.env"
      switching.normalize!
      refute switching.matches_path?("/nested/.env")
      assert switching.matches_path?("/.env")
    end

    test "round trips through JSON" do
      rule = create_rule(kind: "throttle", name: "logins", limit: 5, period: 60, path: "/login")
      restored = Rule.from_json(rule.to_json)

      assert_equal rule.id, restored.id
      assert_equal "logins", restored.name
      assert_equal 5, restored.limit
      assert_equal 60, restored.period
      assert_equal "/login", restored.path
      assert_predicate restored, :persisted?
    end
  end
end
