# frozen_string_literal: true

module Parry
  # Storage backends. RuleStore, Tracker, HoneypotStore and RuleTransfer talk to
  # one of these instead of a database client, so the GUI and the Rack::Attack
  # adapter work the same whichever one is configured.
  #
  # Every backend implements:
  #
  # Rules - stored as the JSON produced by Rule#to_json, keyed by id.
  #   rules                          -> {id => json}
  #   rule(id)                       -> json or nil
  #   rules_count                    -> Integer
  #   save_rule(id, json, kind:, created_at:)  writes and bumps the version
  #   delete_rules(ids)              -> number deleted, bumps the version if any
  #   clear_rules                    deletes every rule and bumps the version
  #   replace_rules({id => json})    swaps the whole set and bumps the version
  #
  # Version counter - changes on every write that affects the rule set.
  #   version                        -> Integer, may be cached (see ActiveRecord)
  #   fresh_version                  -> Integer, never cached
  #   bump_version
  #
  # Caught hosts (honeypots).
  #   caught_hosts                   -> [CaughtHost]
  #   caught_host(ip)                -> CaughtHost or nil
  #   add_caught_host(host)          -> true when stored, false if already caught;
  #                                     bumps the version when stored
  #   remove_caught_host(ip)         -> true when removed; bumps the version
  #   caught_host?(ip), caught_hosts_count, clear_caught_hosts
  #
  # Blocked hosts (tracker).
  #   track(ip:, match_type:, rule:, path:, at:)
  #   tracked_hosts(limit)           -> [BlockedHost], most recent first
  #   tracked_host(ip)               -> BlockedHost or nil
  #   tracked_hosts_count, forget_tracked_host(ip), clear_tracked_hosts
  #   trim_tracked_hosts             drops all but the max_tracked_hosts newest
  module Backends
    def self.build(name)
      case name&.to_sym
      when :active_record
        require_relative "backends/active_record"
        Backends::ActiveRecord.new
      when :redis
        require_relative "backends/redis"
        Backends::Redis.new
      else
        raise Parry::Error, "Unknown Parry backend #{name.inspect}. Use one of: " \
          "#{Configuration::BACKENDS.map(&:inspect).join(", ")}."
      end
    end
  end
end
