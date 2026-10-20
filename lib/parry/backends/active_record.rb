# frozen_string_literal: true

require "json"
require_relative "../application_record"

module Parry
  module Backends
    # Keeps everything in four tables created by `rails generate parry:install`:
    # parry_rules, parry_versions, parry_blocked_hosts and parry_caught_hosts.
    # Works on PostgreSQL, MySQL/MariaDB and SQLite.
    #
    # Two calls sit on the request path and are kept cheap:
    #
    # * +version+ runs on every request (RackAttackAdapter#sync!). It is cached
    #   in-process for +config.version_cache_ttl+ and refreshed straight away
    #   after a write made by this process, so most requests never query.
    # * +track+ runs on every blocked or throttled request. It is a single
    #   upsert; trimming the table to +max_tracked_hosts+ happens only every
    #   +tracker_trim_every+ records or +tracker_trim_interval+ seconds, and
    #   +tracker_write_interval+ can coalesce the writes of one busy address.
    class ActiveRecord
      VERSION_ROW_ID = 1
      # Upper bound on the addresses remembered for tracker_write_interval.
      MAX_PENDING_HOSTS = 10_000
      BLOCKED_HOST_COLUMNS = %i[ip hits rule match_type path first_seen last_seen].freeze

      def initialize(clock: nil)
        @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
        @version_cache = nil
        @tracker_mutex = Mutex.new
        @pending_hits = {}
        @records_since_trim = 0
        @last_trim_at = now
        Parry::ApplicationRecord.apply_connection_config!
      end

      # Rules

      def rules
        with_connection { Records::Rule.pluck(:id, :payload).to_h }
      end

      def rule(id)
        with_connection { Records::Rule.where(id: id.to_s).pick(:payload) }
      end

      def rules_count
        with_connection { Records::Rule.count }
      end

      def save_rule(id, json, kind:, created_at:)
        with_connection do
          Records::Rule.upsert(rule_row(id, json, kind: kind, created_at: created_at))
          bump_version
        end
      end

      def delete_rules(ids)
        ids = Array(ids).map(&:to_s)
        return 0 if ids.empty?

        with_connection do
          count = Records::Rule.where(id: ids).delete_all
          bump_version if count > 0
          count
        end
      end

      def clear_rules
        with_connection do
          Records::Rule.delete_all
          bump_version
        end
      end

      def replace_rules(snapshot)
        rows = snapshot.map do |id, json|
          data = JSON.parse(json)
          rule_row(id, json, kind: data["kind"], created_at: data["created_at"])
        end

        with_connection do
          Records::Rule.transaction do
            Records::Rule.delete_all
            Records::Rule.insert_all!(rows) unless rows.empty?
            bump_version
          end
        end
      end

      # Version

      # The version as this process last saw it, at most version_cache_ttl old.
      #
      # This is where a push-based refresh would plug in: a PostgreSQL
      # LISTEN/NOTIFY listener (NOTIFY parry_version from bump_version) could
      # call expire_version_cache! instead of waiting for the TTL to run out.
      def version
        cached = @version_cache
        return cached[0] if cached && now < cached[1]

        fresh_version
      end

      def fresh_version
        value = with_connection { Records::Version.where(id: VERSION_ROW_ID).pick(:version) }.to_i
        remember_version(value)
      end

      # One atomic UPDATE, so concurrent writers never lose a bump. The row is
      # created on first use.
      def bump_version
        with_connection do
          bumped = Records::Version.where(id: VERSION_ROW_ID).update_all("version = version + 1")
          if bumped.zero?
            Records::Version.insert_all([{id: VERSION_ROW_ID, version: 0}])
            Records::Version.where(id: VERSION_ROW_ID).update_all("version = version + 1")
          end
          fresh_version
        end
      end

      def expire_version_cache!
        @version_cache = nil
      end

      # Caught hosts

      def caught_hosts
        with_connection do
          Records::CaughtHost.pluck(:ip, :rule_id, :rule, :path, :caught_at).map do |ip, rule_id, rule, path, at|
            CaughtHost.new(ip: ip, rule_id: rule_id, rule: rule, path: path, caught_at: at)
          end
        end
      end

      def caught_host(ip)
        row = with_connection do
          Records::CaughtHost.where(ip: ip.to_s).pick(:ip, :rule_id, :rule, :path, :caught_at)
        end
        return nil unless row

        ip, rule_id, rule, path, at = row
        CaughtHost.new(ip: ip, rule_id: rule_id, rule: rule, path: path, caught_at: at)
      end

      def add_caught_host(host)
        row = {ip: host.ip, rule_id: host.rule_id, rule: host.rule, path: host.path, caught_at: host.caught_at&.to_i}

        with_connection do |connection|
          stored = insert_unless_exists(connection, Records::CaughtHost, row, :ip)
          bump_version if stored
          stored
        end
      end

      def remove_caught_host(ip)
        with_connection do
          count = Records::CaughtHost.where(ip: ip.to_s).delete_all
          bump_version if count > 0
          count > 0
        end
      end

      def caught_host?(ip)
        with_connection { Records::CaughtHost.where(ip: ip.to_s).exists? }
      end

      def caught_hosts_count
        with_connection { Records::CaughtHost.count }
      end

      def clear_caught_hosts
        with_connection do
          Records::CaughtHost.delete_all
          bump_version
        end
      end

      # Blocked hosts

      # One upsert: add the hits, refresh last_seen, keep first_seen. Returns
      # false when tracker_write_interval held the write back; the hit is then
      # added by the next write for the same address.
      def track(ip:, match_type:, rule: nil, path: nil, at: Time.now)
        hits = hits_to_write(ip.to_s)
        return false if hits.nil?

        timestamp = at.to_i
        row = {
          ip: ip.to_s, hits: hits, match_type: match_type.to_s, rule: rule&.to_s, path: path&.to_s,
          first_seen: timestamp, last_seen: timestamp
        }

        with_connection do |connection|
          Records::BlockedHost.upsert(row, on_duplicate: Arel.sql(track_update_sql(connection)), **unique_by(connection, :ip))
        end
        trim_tracked_hosts if trim_due?
        true
      end

      def tracked_hosts(limit)
        with_connection do
          Records::BlockedHost.order(last_seen: :desc, ip: :desc).limit(limit).pluck(*BLOCKED_HOST_COLUMNS)
            .map { |values| blocked_host(values) }
        end
      end

      def tracked_host(ip)
        values = with_connection { Records::BlockedHost.where(ip: ip.to_s).pick(*BLOCKED_HOST_COLUMNS) }
        values && blocked_host(values)
      end

      def tracked_hosts_count
        with_connection { Records::BlockedHost.count }
      end

      def forget_tracked_host(ip)
        @tracker_mutex.synchronize { @pending_hits.delete(ip.to_s) }
        with_connection { Records::BlockedHost.where(ip: ip.to_s).delete_all }
        true
      end

      def clear_tracked_hosts
        @tracker_mutex.synchronize { @pending_hits.clear }
        with_connection { Records::BlockedHost.delete_all }
      end

      # Drops everything but the max_tracked_hosts most recent hosts, in the
      # same order Redis would (last_seen, then ip). Returns how many went.
      def trim_tracked_hosts
        max = Parry.config.max_tracked_hosts
        return 0 if max.nil? || max <= 0

        with_connection do
          cutoff = Records::BlockedHost.order(last_seen: :desc, ip: :desc).offset(max).pick(:last_seen, :ip)
          next 0 unless cutoff

          last_seen, ip = cutoff
          table = Records::BlockedHost.arel_table
          older = table[:last_seen].lt(last_seen).or(table[:last_seen].eq(last_seen).and(table[:ip].lteq(ip)))
          Records::BlockedHost.where(older).delete_all
        end
      end

      private

      def now
        @clock.call
      end

      def with_connection(&block)
        Parry::ApplicationRecord.connection_pool.with_connection(&block)
      end

      def remember_version(value)
        ttl = Parry.config.version_cache_ttl.to_f
        @version_cache = ttl.positive? ? [value, now + ttl].freeze : nil
        value
      end

      def rule_row(id, json, kind:, created_at:)
        {id: id.to_s, kind: kind.to_s, payload: json, created_at: created_at&.to_i}
      end

      def blocked_host(values)
        ip, hits, rule, match_type, path, first_seen, last_seen = values
        BlockedHost.new(ip: ip, hits: hits, rule: rule, match_type: match_type, path: path,
          first_seen: first_seen, last_seen: last_seen)
      end

      # MySQL picks the conflicting unique index itself and rejects :unique_by.
      def unique_by(connection, column)
        connection.supports_insert_conflict_target? ? {unique_by: column} : {}
      end

      # INSERT ... ON CONFLICT DO NOTHING, reporting whether the row went in.
      # Where RETURNING is not available (MySQL) a unique violation inside a
      # savepoint tells the same story without poisoning an outer transaction.
      def insert_unless_exists(connection, model, row, column)
        if connection.supports_insert_returning? && connection.supports_insert_conflict_target?
          model.insert_all([row], unique_by: column, returning: [column]).rows.any?
        else
          model.transaction(requires_new: true) { model.insert_all!([row]) }
          true
        end
      rescue ::ActiveRecord::RecordNotUnique
        false
      end

      def track_update_sql(connection)
        table = Records::BlockedHost.quoted_table_name
        hits, match_type, rule, path, last_seen = %w[hits match_type rule path last_seen].map do |column|
          connection.quote_column_name(column)
        end

        [
          "#{hits} = #{table}.#{hits} + #{excluded(connection, hits)}",
          "#{match_type} = #{excluded(connection, match_type)}",
          "#{last_seen} = #{excluded(connection, last_seen)}",
          "#{rule} = COALESCE(#{excluded(connection, rule)}, #{table}.#{rule})",
          "#{path} = COALESCE(#{excluded(connection, path)}, #{table}.#{path})"
        ].join(", ")
      end

      # The value the INSERT tried to write, in the dialect's spelling.
      def excluded(connection, quoted_column)
        mysql?(connection) ? "VALUES(#{quoted_column})" : "excluded.#{quoted_column}"
      end

      def mysql?(connection)
        connection.adapter_name.match?(/mysql|trilogy/i)
      end

      # How many hits to write for +ip+ now, or nil to hold them back because
      # the address was written less than tracker_write_interval ago.
      def hits_to_write(ip)
        interval = Parry.config.tracker_write_interval.to_f
        return 1 unless interval.positive?

        @tracker_mutex.synchronize do
          time = now
          pending, written_at = @pending_hits[ip]

          if written_at && time - written_at < interval
            @pending_hits[ip] = [pending + 1, written_at]
            next nil
          end

          # Re-inserted so the hash stays ordered by last write, oldest first.
          @pending_hits.delete(ip)
          @pending_hits[ip] = [0, time]
          @pending_hits.shift while @pending_hits.size > MAX_PENDING_HOSTS
          (pending || 0) + 1
        end
      end

      def trim_due?
        @tracker_mutex.synchronize do
          @records_since_trim += 1
          every = Parry.config.tracker_trim_every.to_i
          interval = Parry.config.tracker_trim_interval

          due = if every <= 0 && interval.nil?
            true
          else
            (every.positive? && @records_since_trim >= every) ||
              (!interval.nil? && now - @last_trim_at >= interval.to_f)
          end

          if due
            @records_since_trim = 0
            @last_trim_at = now
          end
          due
        end
      end
    end
  end
end
