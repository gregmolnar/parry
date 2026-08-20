# frozen_string_literal: true

module Parry
  class RuleSet
    attr_reader :version, :rules, :caught_hosts

    def initialize(rules = [], version = 0, caught_hosts = {})
      @rules = rules.freeze
      @version = version
      @caught_hosts = caught_hosts.freeze
      @blocklist_rules = rules.select { |rule| rule.kind == "blocklist" }.freeze
      @safelist_rules = rules.select { |rule| rule.kind == "safelist" }.freeze
      @throttle_rules = rules.select(&:throttle?).freeze
      @honeypot_rules = rules.select(&:honeypot?).freeze
      freeze
    end

    def self.empty
      new([], 0, {})
    end

    attr_reader :blocklist_rules, :safelist_rules, :throttle_rules, :honeypot_rules

    def blocklisted?(ip)
      !blocklist_rule_for(ip).nil?
    end

    def safelisted?(ip)
      !safelist_rule_for(ip).nil?
    end

    def blocklist_rule_for(ip)
      @blocklist_rules.find { |rule| rule.matches_ip?(ip) }
    end

    def safelist_rule_for(ip)
      @safelist_rules.find { |rule| rule.matches_ip?(ip) }
    end

    def honeypot_rule_for_path(path)
      @honeypot_rules.find { |rule| rule.matches_path?(path) }
    end

    def caught?(ip)
      !caught_host(ip).nil?
    end

    def caught_host(ip)
      @caught_hosts[ip.to_s]
    end

    def empty?
      @rules.empty? && @caught_hosts.empty?
    end
  end
end
