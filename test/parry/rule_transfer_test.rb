# frozen_string_literal: true

require "test_helper"

module Parry
  class RuleTransferTest < ActiveSupport::TestCase
    def seed_rules
      create_rule(kind: "blocklist", value: "203.0.113.0/24", name: "Scraper")
      create_rule(kind: "honeypot", path_match: "regex", path: "\\.(env|git)", name: "Config probe")
      create_rule(kind: "throttle", name: "logins", limit: 5, period: 60, path: "/login")
    end

    test "exporting describes itself and lists every rule" do
      seed_rules

      data = RuleTransfer.export

      assert_equal RuleTransfer::FORMAT, data["format"]
      assert_equal Parry::VERSION, data["parry_version"]
      assert_kind_of Integer, data["exported_at"]
      assert_equal 3, data["rules"].size
      assert_equal ["Config probe", "Scraper", "logins"], data["rules"].map { |rule| rule[:name] }.sort
    end

    test "exporting an empty store" do
      assert_empty RuleTransfer.export["rules"]
      assert_equal 0, RuleTransfer.import(RuleTransfer.export_json).imported
    end

    test "a round trip keeps every detail" do
      seed_rules
      json = RuleTransfer.export_json
      original = Parry.store.all

      Parry.store.clear
      result = RuleTransfer.import(json)

      assert_predicate result, :ok?
      assert_equal 3, result.imported

      restored = Parry.store.all
      assert_equal original.map(&:to_h), restored.map(&:to_h)

      honeypot = restored.find(&:honeypot?)
      assert_equal "regex", honeypot.path_match
      assert honeypot.matches_path?("/.git/config")
    end

    test "importing twice does not duplicate anything" do
      seed_rules
      json = RuleTransfer.export_json

      assert_predicate RuleTransfer.import(json), :ok?

      assert_equal 3, Parry.store.all.size
    end

    test "merging adds to what is already there" do
      create_rule(kind: "blocklist", value: "198.51.100.1", name: "Existing")
      json = JSON.generate({"rules" => [{"kind" => "blocklist", "value" => "203.0.113.4", "name" => "Imported"}]})

      result = RuleTransfer.import(json)

      assert_predicate result, :ok?
      refute_predicate result, :replaced?
      assert_equal ["Existing", "Imported"], Parry.store.all.map(&:name).sort
    end

    test "replacing throws away what is already there" do
      create_rule(kind: "blocklist", value: "198.51.100.1", name: "Existing")
      json = JSON.generate({"rules" => [{"kind" => "blocklist", "value" => "203.0.113.4", "name" => "Imported"}]})

      result = RuleTransfer.import(json, replace: true)

      assert_predicate result, :ok?
      assert_predicate result, :replaced?
      assert_equal ["Imported"], Parry.store.all.map(&:name)
    end

    test "one bad rule means nothing is imported" do
      json = JSON.generate({"rules" => [
        {"kind" => "blocklist", "value" => "203.0.113.4"},
        {"kind" => "blocklist", "value" => "not-an-ip"}
      ]})

      result = RuleTransfer.import(json)

      refute_predicate result, :ok?
      assert_equal 0, result.imported
      assert_match(/Rule 2 \(not-an-ip\): Value is not a valid IP address/, result.errors.sole)
      assert_empty Parry.store.all
    end

    test "a failed replace leaves the rules it was going to replace alone" do
      seed_rules
      before = Parry.store.all.map(&:to_h)

      json = JSON.generate({"rules" => [
        {"kind" => "blocklist", "value" => "203.0.113.4"},
        {"kind" => "honeypot", "path_match" => "regex", "path" => "wp-(login"}
      ]})

      result = RuleTransfer.import(json, replace: true)

      refute_predicate result, :ok?
      assert_match(/not a valid regular expression/, result.errors.sole)
      assert_equal before, Parry.store.all.map(&:to_h)
    end

    test "the version is bumped so other processes reload" do
      version = Parry.store.version
      json = JSON.generate({"rules" => [{"kind" => "blocklist", "value" => "203.0.113.4"}]})

      RuleTransfer.import(json)

      assert_operator Parry.store.version, :>, version
    end

    test "junk in, a readable complaint out" do
      assert_equal ["The file is empty."], RuleTransfer.import("").errors
      assert_equal ["The file is empty."], RuleTransfer.import("   ").errors
      assert_match(/not valid JSON/, RuleTransfer.import("{oh dear").errors.sole)
      assert_match(/Expected an export/, RuleTransfer.import('{"nope": 1}').errors.sole)
      assert_equal ["The file contains no rules."], RuleTransfer.import('{"rules": []}').errors
      assert_match(/could not be read/, RuleTransfer.import('{"rules": ["nope"]}').errors.sole)
    end

    test "a file over the size limit is refused without being parsed" do
      oversized = "x" * (RuleTransfer::MAX_BYTES + 1)

      result = RuleTransfer.import(oversized)

      assert_match(/bigger than/, result.errors.sole)
    end

    test "a bare list of rules is accepted" do
      result = RuleTransfer.import(JSON.generate([{"kind" => "blocklist", "value" => "203.0.113.4"}]))

      assert_predicate result, :ok?
      assert_equal 1, result.imported
    end

    test "imported rules take effect" do
      json = JSON.generate({"rules" => [{"kind" => "blocklist", "value" => "203.0.113.4"}]})

      RuleTransfer.import(json)
      Parry.adapter.sync!(force: true)

      assert Parry.adapter.rule_set.blocklisted?("203.0.113.4")
    end

    test "the filename carries the time it was taken" do
      assert_equal "parry-rules-20260822-091500.json", RuleTransfer.filename(at: Time.new(2026, 8, 22, 9, 15, 0))
    end
  end
end
