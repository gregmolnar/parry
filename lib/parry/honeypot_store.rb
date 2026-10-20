# frozen_string_literal: true

module Parry
  class HoneypotStore
    def all
      backend.caught_hosts
    end

    def to_h
      all.each_with_object({}) { |host, index| index[host.ip] = host }
    end

    def find(ip)
      backend.caught_host(ip)
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

      backend.add_caught_host(host)
    end

    def release(ip)
      backend.remove_caught_host(ip)
    end

    def caught?(ip)
      backend.caught_host?(ip)
    end

    def count
      backend.caught_hosts_count
    end

    def clear
      backend.clear_caught_hosts
    end

    # Redis key name, kept for anyone reading Parry's Redis data directly.
    def caught_key
      Backends::Redis.key("caught")
    end

    private

    def backend
      Parry.backend
    end
  end
end
