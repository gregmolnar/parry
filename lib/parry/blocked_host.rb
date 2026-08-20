# frozen_string_literal: true

module Parry
  class BlockedHost
    attr_reader :ip, :hits, :rule, :match_type, :path, :first_seen, :last_seen

    def self.from_hash(ip, hash)
      return nil if hash.nil? || hash.empty?

      new(
        ip: ip,
        hits: hash["hits"].to_i,
        rule: hash["rule"],
        match_type: hash["match_type"],
        path: hash["path"],
        first_seen: hash["first_seen"],
        last_seen: hash["last_seen"]
      )
    end

    def initialize(ip:, hits: 0, rule: nil, match_type: nil, path: nil, first_seen: nil, last_seen: nil)
      @ip = ip
      @hits = hits.to_i
      @rule = rule
      @match_type = match_type
      @path = path
      @first_seen = to_time(first_seen)
      @last_seen = to_time(last_seen)
    end

    def throttled?
      match_type.to_s == "throttle"
    end

    def blocklisted?
      match_type.to_s == "blocklist"
    end

    def caught?
      match_type.to_s == "honeypot"
    end

    def to_param
      ip
    end

    private

    def to_time(value)
      Time.at(value.to_i) if value
    end
  end
end
