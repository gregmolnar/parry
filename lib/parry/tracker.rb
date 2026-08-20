# frozen_string_literal: true

module Parry
  class Tracker
    def record(ip:, match_type:, rule: nil, path: nil, at: Time.now)
      return if ip.nil? || ip.to_s.empty?

      timestamp = at.to_i
      key = host_key(ip)
      Parry.with_redis do |redis|
        redis.multi do |tx|
          tx.hincrby(key, "hits", 1)
          tx.hset(key, "ip", ip.to_s, "match_type", match_type.to_s, "last_seen", timestamp.to_s)
          tx.hsetnx(key, "first_seen", timestamp.to_s)
          tx.hset(key, "rule", rule.to_s) if rule
          tx.hset(key, "path", path.to_s) if path
          tx.zadd(index_key, timestamp, ip.to_s)
        end
      end
      trim!
    end

    def all(limit: 100)
      ips = Parry.with_redis { |redis| redis.zrevrange(index_key, 0, limit - 1) }
      return [] if ips.empty?

      hashes = Parry.with_redis do |redis|
        redis.pipelined { |pipeline| ips.each { |ip| pipeline.hgetall(host_key(ip)) } }
      end

      ips.zip(hashes).filter_map { |ip, hash| BlockedHost.from_hash(ip, hash) }
    end

    def find(ip)
      hash = Parry.with_redis { |redis| redis.hgetall(host_key(ip)) }
      BlockedHost.from_hash(ip, hash)
    end

    def count
      Parry.with_redis { |redis| redis.zcard(index_key) }
    end

    def forget(ip)
      Parry.with_redis do |redis|
        redis.multi do |tx|
          tx.zrem(index_key, ip.to_s)
          tx.del(host_key(ip))
        end
      end
      true
    end

    def clear
      Parry.with_redis do |redis|
        ips = redis.zrange(index_key, 0, -1)
        redis.del(*ips.map { |ip| host_key(ip) }) unless ips.empty?
        redis.del(index_key)
      end
    end

    def index_key
      "#{Parry.config.key_prefix}:blocked_hosts"
    end

    def host_key(ip)
      "#{Parry.config.key_prefix}:blocked_host:#{ip}"
    end

    private

    def trim!
      max = Parry.config.max_tracked_hosts
      return if max.nil? || max <= 0

      Parry.with_redis do |redis|
        excess = redis.zcard(index_key) - max
        next if excess <= 0

        victims = redis.zrange(index_key, 0, excess - 1)
        next if victims.empty?

        redis.multi do |tx|
          tx.zrem(index_key, victims)
          tx.del(*victims.map { |ip| host_key(ip) })
        end
      end
    end
  end
end
