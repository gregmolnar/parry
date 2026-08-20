# frozen_string_literal: true

require "rack/attack"

module Parry
  # Bridges the rules stored in Redis into Rack::Attack.
  #
  # A safelist and a blocklist check are registered once; both consult the
  # current snapshot of the rules. Throttles have to be registered as real
  # Rack::Attack throttles, so the snapshot is refreshed whenever the version
  # counter in Redis changes - that is what makes GUI edits visible to every
  # process without a redeploy.
  class RackAttackAdapter
    SAFELIST_NAME = "parry/safelist"
    BLOCKLIST_NAME = "parry/blocklist"
    THROTTLE_PREFIX = "parry/throttle/"
    THROTTLE_NAME_PATTERN = /\A#{Regexp.escape(THROTTLE_PREFIX)}(?<id>.+)\z/
    # Set while a request is being checked, so the tracker can report which rule
    # matched without looking it up again.
    MATCHED_RULE_KEY = "parry.matched_rule"

    def initialize
      @mutex = Mutex.new
      @rule_set = RuleSet.empty
      @version = nil
      @installed = false
      @subscribed = false
    end

    def installed?
      @installed
    end

    # The snapshot every request is checked against.
    attr_reader :rule_set

    # Registers the Rack::Attack hooks. Safe to call more than once.
    def install!
      return false if @installed

      adapter = self

      Rack::Attack.safelist(SAFELIST_NAME) do |request|
        # Runs on every request, before any blocklist or throttle, which makes
        # it the natural place to pick up rule changes.
        adapter.sync!
        adapter.rule_set.safelisted?(request.ip)
      end

      Rack::Attack.blocklist(BLOCKLIST_NAME) do |request|
        adapter.blocked?(request)
      end

      subscribe!
      @installed = true
    end

    # Refreshes the snapshot when the version counter changed. Redis problems
    # must not take the application down, so the last known snapshot is kept.
    def sync!(force: false)
      current = Parry.store.version
      return @rule_set if !force && @version == current

      @mutex.synchronize do
        return @rule_set if !force && @version == current

        rule_set = Parry.store.rule_set
        register_throttles(rule_set)
        @rule_set = rule_set
        @version = rule_set.version
      end
      @rule_set
    rescue => e
      Parry.logger.error("[parry] could not load rules: #{e.class}: #{e.message}")
      @rule_set
    end

    # Decides whether the request is blocked, and springs any honeypot it walks
    # into. Runs after the safelist check, so a safelisted host is never
    # caught.
    def blocked?(request)
      ip = request.ip
      snapshot = @rule_set

      if (rule = snapshot.blocklist_rule_for(ip))
        request.env[MATCHED_RULE_KEY] = "Blocklist: #{rule.label}"
        return true
      end

      if (caught = snapshot.caught_host(ip))
        request.env[MATCHED_RULE_KEY] = honeypot_label(caught.rule)
        return true
      end

      if (rule = snapshot.honeypot_rule_for_path(request.path))
        catch_host(ip, rule, request.path)
        request.env[MATCHED_RULE_KEY] = honeypot_label(rule.label)
        return true
      end

      false
    end

    # Removes the Parry blocklist rules covering +ip+, resets the throttle
    # counters recorded against it and forgets it in the blocked hosts list.
    def unblock(ip)
      removed = Parry.store.delete_matching_ip(ip, kinds: ["blocklist"])
      Parry.honeypots.release(ip)
      reset_throttle_counters(ip)
      Parry.tracker.forget(ip)
      sync!(force: true)
      removed
    end

    # Resets the current counter window of every registered throttle for +ip+,
    # including throttles the host application defined itself.
    def reset_throttle_counters(ip)
      discriminator = normalize_discriminator(ip)
      Rack::Attack.throttles.each do |name, throttle|
        period = throttle.period
        next if period.respond_to?(:call)

        Rack::Attack.cache.reset_count("#{name}:#{discriminator}", period)
      end
      true
    rescue => e
      Parry.logger.warn("[parry] could not reset throttle counters for #{ip}: #{e.class}: #{e.message}")
      false
    end

    # Records blocked and throttled requests so they show up in the GUI.
    def subscribe!
      return false if @subscribed || !Parry.config.track_events

      adapter = self
      ActiveSupport::Notifications.subscribe(/\.rack_attack\z/) do |name, _start, _finish, _id, payload|
        adapter.handle_event(name.split(".").first, payload[:request])
      end
      @subscribed = true
    end

    def handle_event(match_type, request)
      return unless %w[blocklist throttle].include?(match_type)
      return if request.nil?

      Parry.tracker.record(
        ip: request.ip,
        match_type: match_type,
        rule: rule_label_for(match_type, request),
        path: request.path
      )
    rescue => e
      Parry.logger.warn("[parry] could not record blocked host: #{e.class}: #{e.message}")
    end

    # Forgets the registered hooks. Only useful in tests.
    def reset!
      @rule_set = RuleSet.empty
      @version = nil
      @installed = false
    end

    private

    # Records the host, but a Redis failure must not let it through: the
    # caller blocks the request either way.
    def catch_host(ip, rule, path)
      Parry.honeypots.record(ip, rule: rule, path: path)
    rescue => e
      Parry.logger.error("[parry] could not record caught host #{ip}: #{e.class}: #{e.message}")
      false
    end

    def honeypot_label(label)
      label.to_s.empty? ? "Honeypot" : "Honeypot: #{label}"
    end

    def rule_label_for(match_type, request)
      known = request.env[MATCHED_RULE_KEY]
      return known if known

      matched = request.env["rack.attack.matched"]

      case matched
      when BLOCKLIST_NAME
        rule = @rule_set.blocklist_rule_for(request.ip)
        rule ? "Blocklist: #{rule.label}" : "Blocklist"
      when THROTTLE_NAME_PATTERN
        rule = @rule_set.throttle_rules.find { |candidate| candidate.id == $~[:id] }
        rule ? "Throttle: #{rule.label}" : "Throttle"
      else
        matched.to_s
      end
    end

    def register_throttles(rule_set)
      Rack::Attack.throttles.delete_if { |name, _| name.start_with?(THROTTLE_PREFIX) }

      rule_set.throttle_rules.each do |rule|
        path_prefix = rule.path.to_s
        Rack::Attack.throttle("#{THROTTLE_PREFIX}#{rule.id}", limit: rule.limit, period: rule.period) do |request|
          request.ip if path_prefix.empty? || request.path.start_with?(path_prefix)
        end
      end
    end

    def normalize_discriminator(value)
      normalizer = Rack::Attack.throttle_discriminator_normalizer
      normalizer ? normalizer.call(value) : value
    end
  end
end
