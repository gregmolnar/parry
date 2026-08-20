# frozen_string_literal: true

require "json"

module Parry
  class CaughtHost
    attr_reader :ip, :rule_id, :rule, :path, :caught_at

    def self.from_json(ip, json)
      data = JSON.parse(json)
      new(ip: ip, rule_id: data["rule_id"], rule: data["rule"], path: data["path"],
        caught_at: data["caught_at"])
    rescue JSON::ParserError
      nil
    end

    def initialize(ip:, rule_id: nil, rule: nil, path: nil, caught_at: nil)
      @ip = ip.to_s
      @rule_id = rule_id
      @rule = rule
      @path = path
      @caught_at = caught_at.nil? ? nil : Time.at(caught_at.to_i)
    end

    def to_h
      {rule_id: rule_id, rule: rule, path: path, caught_at: caught_at&.to_i}
    end

    def to_json(*args)
      to_h.to_json(*args)
    end
  end
end
