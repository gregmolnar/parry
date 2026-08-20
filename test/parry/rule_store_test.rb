# frozen_string_literal: true

require "test_helper"

module Parry
  class RuleStoreTest < ActiveSupport::TestCase
    test "saving assigns an id and a creation time" do
      rule = Rule.new(kind: "blocklist", value: "203.0.113.4")

      assert Parry.store.save(rule)
      assert_predicate rule.id, :present?
      assert_predicate rule.created_at, :present?
      assert_predicate rule, :persisted?
      assert_equal 1, Parry.store.count
    end

    test "an invalid rule is not stored" do
      rule = Rule.new(kind: "blocklist", value: "nope")

      refute Parry.store.save(rule)
      assert_equal 0, Parry.store.count
    end

    test "find and where" do
      blocked = create_rule(kind: "blocklist", value: "203.0.113.4")
      create_rule(kind: "safelist", value: "198.51.100.1")

      assert_equal blocked.id, Parry.store.find(blocked.id).id
      assert_nil Parry.store.find("missing")
      assert_equal ["203.0.113.4"], Parry.store.where(kind: "blocklist").map(&:value)
      assert_equal 2, Parry.store.all.size
    end

    test "delete removes the rule" do
      rule = create_rule(kind: "blocklist", value: "203.0.113.4")

      assert Parry.store.delete(rule.id)
      refute Parry.store.delete(rule.id)
      assert_equal 0, Parry.store.count
    end

    test "delete_matching_ip removes every blocklist rule covering the address" do
      create_rule(kind: "blocklist", value: "203.0.113.0/24")
      create_rule(kind: "blocklist", value: "203.0.113.7")
      kept = create_rule(kind: "blocklist", value: "198.51.100.1")
      safe = create_rule(kind: "safelist", value: "203.0.113.7")

      removed = Parry.store.delete_matching_ip("203.0.113.7")

      assert_equal 2, removed.size
      assert_equal [kept.id, safe.id].sort, Parry.store.all.map(&:id).sort
    end

    test "the version changes on every write" do
      initial = Parry.store.version

      rule = create_rule(kind: "blocklist", value: "203.0.113.4")
      after_create = Parry.store.version
      assert_operator after_create, :>, initial

      Parry.store.delete(rule.id)
      assert_operator Parry.store.version, :>, after_create
    end

    test "rule_set groups the rules by kind" do
      create_rule(kind: "blocklist", value: "203.0.113.0/24")
      create_rule(kind: "safelist", value: "203.0.113.7")
      create_rule(kind: "throttle", name: "logins", limit: 5, period: 60)

      rule_set = Parry.store.rule_set

      assert rule_set.blocklisted?("203.0.113.9")
      refute rule_set.blocklisted?("198.51.100.1")
      assert rule_set.safelisted?("203.0.113.7")
      assert_equal ["logins"], rule_set.throttle_rules.map(&:name)
      assert_equal Parry.store.version, rule_set.version
    end
  end
end
