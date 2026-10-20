# frozen_string_literal: true

require "securerandom"

module Parry
  class RuleStore
    def all
      backend.rules.values.filter_map { |json| Rule.from_json(json) }.sort_by { |rule| [rule.created_at || 0, rule.id.to_s] }
    end

    def where(kind:)
      all.select { |rule| rule.kind == kind.to_s }
    end

    def find(id)
      json = backend.rule(id)
      json && Rule.from_json(json)
    end

    def count
      backend.rules_count
    end

    def save(rule)
      rule.id ||= SecureRandom.hex(8)
      rule.normalize!
      return false unless rule.valid?

      rule.created_at ||= Time.now.to_i
      backend.save_rule(rule.id, rule.to_json, kind: rule.kind, created_at: rule.created_at)
      rule.persisted = true
      true
    end

    def delete(id)
      backend.delete_rules([id]) > 0
    end

    def delete_matching_ip(ip, kinds: ["blocklist"])
      kinds = Array(kinds).map(&:to_s)
      matching = all.select { |rule| kinds.include?(rule.kind) && rule.matches_ip?(ip) }
      return matching if matching.empty?

      backend.delete_rules(matching.map(&:id))
      matching
    end

    # Checked on every request. The ActiveRecord backend answers from an
    # in-process cache that is at most +config.version_cache_ttl+ old.
    def version
      backend.version
    end

    def bump_version
      backend.bump_version
    end

    def rule_set
      current = backend.fresh_version
      RuleSet.new(all, current, Parry.honeypots.to_h)
    end

    def clear
      backend.clear_rules
    end

    # Redis key names, kept for anyone reading Parry's Redis data directly.
    def rules_key
      Backends::Redis.key("rules")
    end

    def version_key
      Backends::Redis.key("rules_version")
    end

    private

    def backend
      Parry.backend
    end
  end
end
