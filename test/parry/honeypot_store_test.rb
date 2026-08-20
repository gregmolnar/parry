# frozen_string_literal: true

require "test_helper"

module Parry
  class HoneypotStoreTest < ActiveSupport::TestCase
    test "catching records the host" do
      rule = create_rule(kind: "honeypot", path: "/.env", name: "Env probe")

      assert Parry.honeypots.record("203.0.113.4", rule: rule, path: "/.env")

      host = Parry.honeypots.find("203.0.113.4")
      assert_equal "203.0.113.4", host.ip
      assert_equal rule.id, host.rule_id
      assert_equal "Env probe", host.rule
      assert_equal "/.env", host.path
      assert_kind_of Time, host.caught_at
      assert Parry.honeypots.caught?("203.0.113.4")
      assert_equal 1, Parry.honeypots.count
    end

    test "catching a host twice keeps the first record and the version" do
      rule = create_rule(kind: "honeypot", path: "/.env")

      assert Parry.honeypots.record("203.0.113.4", rule: rule, path: "/.env", at: Time.at(1000))
      version = Parry.store.version

      refute Parry.honeypots.record("203.0.113.4", rule: rule, path: "/other", at: Time.at(2000))

      assert_equal version, Parry.store.version
      assert_equal "/.env", Parry.honeypots.find("203.0.113.4").path
      assert_equal 1, Parry.honeypots.count
    end

    test "catching bumps the version so other processes notice" do
      rule = create_rule(kind: "honeypot", path: "/.env")
      version = Parry.store.version

      Parry.honeypots.record("203.0.113.4", rule: rule, path: "/.env")

      assert_operator Parry.store.version, :>, version
    end

    test "releasing removes the host and bumps the version" do
      rule = create_rule(kind: "honeypot", path: "/.env")
      Parry.honeypots.record("203.0.113.4", rule: rule, path: "/.env")
      version = Parry.store.version

      assert Parry.honeypots.release("203.0.113.4")
      assert_operator Parry.store.version, :>, version
      refute Parry.honeypots.caught?("203.0.113.4")

      refute Parry.honeypots.release("203.0.113.4")
    end

    test "a blank address is not caught" do
      refute Parry.honeypots.record(nil)
      refute Parry.honeypots.record("")
      assert_equal 0, Parry.honeypots.count
    end

    test "the caught hosts end up in the rule set" do
      rule = create_rule(kind: "honeypot", path: "/.env")
      Parry.honeypots.record("203.0.113.4", rule: rule, path: "/.env")

      rule_set = Parry.store.rule_set

      assert rule_set.caught?("203.0.113.4")
      refute rule_set.caught?("198.51.100.9")
      assert_equal "/.env", rule_set.caught_host("203.0.113.4").path
    end
  end
end
