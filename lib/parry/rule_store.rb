# frozen_string_literal: true

require "securerandom"

module Parry
  class RuleStore
    def all
      raw = Parry.with_redis { |redis| redis.hgetall(rules_key) }
      raw.values.filter_map { |json| Rule.from_json(json) }.sort_by { |rule| [rule.created_at || 0, rule.id.to_s] }
    end

    def where(kind:)
      all.select { |rule| rule.kind == kind.to_s }
    end

    def find(id)
      json = Parry.with_redis { |redis| redis.hget(rules_key, id.to_s) }
      json && Rule.from_json(json)
    end

    def count
      Parry.with_redis { |redis| redis.hlen(rules_key) }
    end

    def save(rule)
      rule.id ||= SecureRandom.hex(8)
      rule.normalize!
      return false unless rule.valid?

      rule.created_at ||= Time.now.to_i
      Parry.with_redis do |redis|
        redis.hset(rules_key, rule.id, rule.to_json)
        redis.incr(version_key)
      end
      rule.persisted = true
      true
    end

    def delete(id)
      deleted = Parry.with_redis do |redis|
        count = redis.hdel(rules_key, id.to_s)
        redis.incr(version_key) if count > 0
        count
      end
      deleted > 0
    end

    def delete_matching_ip(ip, kinds: ["blocklist"])
      kinds = Array(kinds).map(&:to_s)
      matching = all.select { |rule| kinds.include?(rule.kind) && rule.matches_ip?(ip) }
      return matching if matching.empty?

      Parry.with_redis do |redis|
        redis.hdel(rules_key, matching.map(&:id))
        redis.incr(version_key)
      end
      matching
    end

    def version
      Parry.with_redis { |redis| redis.get(version_key) }.to_i
    end

    def bump_version
      Parry.with_redis { |redis| redis.incr(version_key) }
    end

    def rule_set
      current = version
      RuleSet.new(all, current, Parry.honeypots.to_h)
    end

    def clear
      Parry.with_redis do |redis|
        redis.del(rules_key)
        redis.incr(version_key)
      end
    end

    def rules_key
      "#{Parry.config.key_prefix}:rules"
    end

    def version_key
      "#{Parry.config.key_prefix}:rules_version"
    end
  end
end
