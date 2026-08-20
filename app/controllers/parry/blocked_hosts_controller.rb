# frozen_string_literal: true

module Parry
  class BlockedHostsController < ApplicationController
    PER_PAGE = 50
    # Fallback window for reading the tracker when host tracking is uncapped.
    MAX_LISTED = 1000

    def index
      @rule_set = Parry.store.rule_set
      hosts = hosts_with_caught(tracked_hosts)

      @total = hosts.size
      @total_pages = [(@total / PER_PAGE.to_f).ceil, 1].max
      @page = requested_page(@total_pages)
      @offset = (@page - 1) * PER_PAGE
      @hosts = hosts[@offset, PER_PAGE] || []
    end

    def unblock
      ip = params[:ip].to_s

      if ip.empty?
        redirect_to blocked_hosts_path(page: page_param), alert: "No host given."
        return
      end

      was_caught = Parry.honeypots.caught?(ip)
      removed = Parry.unblock(ip)

      # Back to the page they were looking at, not the top of the list.
      redirect_to blocked_hosts_path(page: page_param), notice: unblocked_notice(ip, removed, was_caught)
    end

    private

    # The tracker trims itself to max_tracked_hosts, so reading that many covers
    # everything it holds.
    def tracked_hosts
      limit = Parry.config.max_tracked_hosts.to_i

      Parry.tracker.all(limit: limit.positive? ? limit : MAX_LISTED)
    end

    def requested_page(total_pages)
      page = params[:page].to_i
      return 1 if page < 1

      [page, total_pages].min
    end

    # Kept out of the URL when it is the first page.
    def page_param
      page = params[:page].to_i

      (page > 1) ? page : nil
    end

    def unblocked_notice(ip, removed, was_caught)
      changes = []
      changes << "removed #{removed.size} blocklist #{"rule".pluralize(removed.size)}" if removed.any?
      changes << "released it from the honeypot" if was_caught
      changes << "reset its throttle counters" if changes.empty?

      "Unblocked #{ip} and #{changes.to_sentence}."
    end

    def hosts_with_caught(tracked)
      seen = tracked.map(&:ip)

      caught = @rule_set.caught_hosts.each_value.reject { |host| seen.include?(host.ip) }.map do |host|
        BlockedHost.new(
          ip: host.ip,
          match_type: "honeypot",
          rule: host.rule.present? ? "Honeypot: #{host.rule}" : "Honeypot",
          path: host.path,
          first_seen: host.caught_at&.to_i,
          last_seen: host.caught_at&.to_i
        )
      end

      (tracked + caught).sort_by { |host| -(host.last_seen&.to_i || 0) }
    end
  end
end
