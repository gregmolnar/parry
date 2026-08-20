# frozen_string_literal: true

module Parry
  class HoneypotStore
    def all
      raw = Parry.with_redis { |redis| redis.hgetall(caught_key) }
      raw.filter_map { |ip, json| CaughtHost.from_json(ip, json) }
    end

    def to_h
      all.each_with_object({}) { |host, index| index[host.ip] = host }
    end

    def find(ip)
      json = Parry.with_redis { |redis| redis.hget(caught_key, ip.to_s) }
      json && CaughtHost.from_json(ip.to_s, json)
    end

    def record(ip, rule: nil, path: nil, at: Time.now)
      return false if ip.nil? || ip.to_s.empty?

      host = CaughtHost.new(
        ip: ip,
        rule_id: rule&.id,
        rule: rule&.label,
        path: path,
        caught_at: at.to_i
      )

      added = Parry.with_redis do |redis|
        stored = redis.hsetnx(caught_key, host.ip, host.to_json)
        redis.incr(version_key) if stored
        stored
      end
      !!added
    end

    def release(ip)
      removed = Parry.with_redis do |redis|
        count = redis.hdel(caught_key, ip.to_s)
        redis.incr(version_key) if count > 0
        count
      end
      removed > 0
    end

    def caught?(ip)
      Parry.with_redis { |redis| redis.hexists(caught_key, ip.to_s) }
    end

    def count
      Parry.with_redis { |redis| redis.hlen(caught_key) }
    end

    def clear
      Parry.with_redis do |redis|
        redis.del(caught_key)
        redis.incr(version_key)
      end
    end

    def caught_key
      "#{Parry.config.key_prefix}:caught"
    end

    private

    def version_key
      Parry.store.version_key
    end
  end
end
