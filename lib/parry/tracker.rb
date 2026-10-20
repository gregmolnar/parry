# frozen_string_literal: true

module Parry
  class Tracker
    def record(ip:, match_type:, rule: nil, path: nil, at: Time.now)
      return if ip.nil? || ip.to_s.empty?

      backend.track(ip: ip, match_type: match_type, rule: rule, path: path, at: at)
    end

    def all(limit: 100)
      backend.tracked_hosts(limit)
    end

    def find(ip)
      backend.tracked_host(ip)
    end

    def count
      backend.tracked_hosts_count
    end

    def forget(ip)
      backend.forget_tracked_host(ip)
    end

    def clear
      backend.clear_tracked_hosts
    end

    # Drops the oldest hosts beyond +config.max_tracked_hosts+. The Redis
    # backend does this on every record; the ActiveRecord backend only every so
    # often, so it can also be called from a scheduled job.
    def trim!
      backend.trim_tracked_hosts
    end

    # Redis key names, kept for anyone reading Parry's Redis data directly.
    def index_key
      Backends::Redis.key("blocked_hosts")
    end

    def host_key(ip)
      Backends::Redis.key("blocked_host:#{ip}")
    end

    private

    def backend
      Parry.backend
    end
  end
end
