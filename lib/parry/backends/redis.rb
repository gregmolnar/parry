# frozen_string_literal: true

module Parry
  module Backends
    # Keeps everything in Redis:
    #
    #   <prefix>:rules                  hash of rule id => rule JSON
    #   <prefix>:rules_version          counter bumped on every write
    #   <prefix>:caught                 hash of ip => caught host JSON
    #   <prefix>:blocked_hosts          zset of ip scored by last_seen
    #   <prefix>:blocked_host:<ip>      hash with the host's details
    class Redis
      def self.require_client!
        require "redis"
      rescue LoadError
        raise Parry::Error, "Parry's :redis backend needs the redis gem. Add `gem \"redis\"` to your Gemfile, " \
          "or switch to the ActiveRecord backend with `config.backend = :active_record`."
      end

      def self.key(name, prefix: Parry.config.key_prefix)
        "#{prefix}:#{name}"
      end

      def initialize
        self.class.require_client!
      end

      # Rules

      def rules
        with_redis { |redis| redis.hgetall(rules_key) }
      end

      def rule(id)
        with_redis { |redis| redis.hget(rules_key, id.to_s) }
      end

      def rules_count
        with_redis { |redis| redis.hlen(rules_key) }
      end

      def save_rule(id, json, kind: nil, created_at: nil)
        with_redis do |redis|
          redis.hset(rules_key, id, json)
          redis.incr(version_key)
        end
      end

      def delete_rules(ids)
        ids = Array(ids).map(&:to_s)
        return 0 if ids.empty?

        with_redis do |redis|
          count = redis.hdel(rules_key, ids)
          redis.incr(version_key) if count > 0
          count
        end
      end

      def clear_rules
        with_redis do |redis|
          redis.del(rules_key)
          redis.incr(version_key)
        end
      end

      def replace_rules(snapshot)
        with_redis do |redis|
          redis.del(rules_key)
          snapshot.each { |id, json| redis.hset(rules_key, id, json) }
          redis.incr(version_key)
        end
      end

      # Version

      def version
        with_redis { |redis| redis.get(version_key) }.to_i
      end
      alias_method :fresh_version, :version

      def bump_version
        with_redis { |redis| redis.incr(version_key) }
      end

      # Caught hosts

      def caught_hosts
        raw = with_redis { |redis| redis.hgetall(caught_key) }
        raw.filter_map { |ip, json| CaughtHost.from_json(ip, json) }
      end

      def caught_host(ip)
        json = with_redis { |redis| redis.hget(caught_key, ip.to_s) }
        json && CaughtHost.from_json(ip.to_s, json)
      end

      def add_caught_host(host)
        added = with_redis do |redis|
          stored = redis.hsetnx(caught_key, host.ip, host.to_json)
          redis.incr(version_key) if stored
          stored
        end
        !!added
      end

      def remove_caught_host(ip)
        removed = with_redis do |redis|
          count = redis.hdel(caught_key, ip.to_s)
          redis.incr(version_key) if count > 0
          count
        end
        removed > 0
      end

      def caught_host?(ip)
        with_redis { |redis| redis.hexists(caught_key, ip.to_s) }
      end

      def caught_hosts_count
        with_redis { |redis| redis.hlen(caught_key) }
      end

      def clear_caught_hosts
        with_redis do |redis|
          redis.del(caught_key)
          redis.incr(version_key)
        end
      end

      # Blocked hosts

      def track(ip:, match_type:, rule: nil, path: nil, at: Time.now)
        timestamp = at.to_i
        key = host_key(ip)
        with_redis do |redis|
          redis.multi do |tx|
            tx.hincrby(key, "hits", 1)
            tx.hset(key, "ip", ip.to_s, "match_type", match_type.to_s, "last_seen", timestamp.to_s)
            tx.hsetnx(key, "first_seen", timestamp.to_s)
            tx.hset(key, "rule", rule.to_s) if rule
            tx.hset(key, "path", path.to_s) if path
            tx.zadd(index_key, timestamp, ip.to_s)
          end
        end
        trim_tracked_hosts
      end

      def tracked_hosts(limit)
        ips = with_redis { |redis| redis.zrevrange(index_key, 0, limit - 1) }
        return [] if ips.empty?

        hashes = with_redis do |redis|
          redis.pipelined { |pipeline| ips.each { |ip| pipeline.hgetall(host_key(ip)) } }
        end

        ips.zip(hashes).filter_map { |ip, hash| BlockedHost.from_hash(ip, hash) }
      end

      def tracked_host(ip)
        hash = with_redis { |redis| redis.hgetall(host_key(ip)) }
        BlockedHost.from_hash(ip, hash)
      end

      def tracked_hosts_count
        with_redis { |redis| redis.zcard(index_key) }
      end

      def forget_tracked_host(ip)
        with_redis do |redis|
          redis.multi do |tx|
            tx.zrem(index_key, ip.to_s)
            tx.del(host_key(ip))
          end
        end
        true
      end

      def clear_tracked_hosts
        with_redis do |redis|
          ips = redis.zrange(index_key, 0, -1)
          redis.del(*ips.map { |ip| host_key(ip) }) unless ips.empty?
          redis.del(index_key)
        end
      end

      def trim_tracked_hosts
        max = Parry.config.max_tracked_hosts
        return if max.nil? || max <= 0

        with_redis do |redis|
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

      # Keys

      def rules_key
        self.class.key("rules")
      end

      def version_key
        self.class.key("rules_version")
      end

      def caught_key
        self.class.key("caught")
      end

      def index_key
        self.class.key("blocked_hosts")
      end

      def host_key(ip)
        self.class.key("blocked_host:#{ip}")
      end

      # Wipes the whole Redis database. Only meant for tests.
      def flush!
        with_redis(&:flushdb)
      end

      private

      def with_redis(&block)
        Parry.with_redis(&block)
      end
    end
  end
end
