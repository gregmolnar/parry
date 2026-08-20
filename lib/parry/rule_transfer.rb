# frozen_string_literal: true

require "json"

module Parry
  class RuleTransfer
    FORMAT = 1
    MAX_BYTES = 1_048_576

    Result = Struct.new(:imported, :errors, :replaced, keyword_init: true) do
      def ok?
        errors.empty?
      end

      def replaced?
        !!replaced
      end
    end

    class << self
      def export
        {
          "format" => FORMAT,
          "parry_version" => Parry::VERSION,
          "exported_at" => Time.now.to_i,
          "rules" => Parry.store.all.map(&:to_h)
        }
      end

      def export_json
        JSON.pretty_generate(export)
      end

      def filename(at: Time.now)
        "parry-rules-#{at.strftime("%Y%m%d-%H%M%S")}.json"
      end

      def import(payload, replace: false)
        payload = payload.to_s
        return failure("The file is empty.") if payload.strip.empty?
        return failure("The file is bigger than #{MAX_BYTES / 1024}KB.") if payload.bytesize > MAX_BYTES

        data = begin
          JSON.parse(payload)
        rescue JSON::ParserError => e
          return failure("The file is not valid JSON (#{e.message.lines.first.to_s.strip}).")
        end

        entries = entries_in(data)
        return failure(%(No rules found. Expected an export with a "rules" list.)) if entries.nil?
        return failure("The file contains no rules.") if entries.empty?

        apply(entries, replace: replace)
      end

      private

      def entries_in(data)
        case data
        when Hash then data["rules"].is_a?(Array) ? data["rules"] : nil
        when Array then data
        end
      end

      def apply(entries, replace:)
        snapshot = Parry.with_redis { |redis| redis.hgetall(Parry.store.rules_key) }
        errors = []
        imported = 0

        Parry.store.clear if replace

        entries.each_with_index do |attrs, index|
          rule = build(attrs)

          if rule.nil?
            errors << "Rule #{index + 1} could not be read."
          elsif Parry.store.save(rule)
            imported += 1
          else
            errors << "Rule #{index + 1}#{label_for(rule)}: #{rule.errors.full_messages.to_sentence}."
          end
        end

        if errors.any?
          restore(snapshot)
          return Result.new(imported: 0, errors: errors, replaced: false)
        end

        Result.new(imported: imported, errors: [], replaced: replace)
      end

      def build(attrs)
        return nil unless attrs.is_a?(Hash)

        rule = Rule.from_json(attrs.to_json)
        rule&.persisted = false
        rule
      end

      def label_for(rule)
        label = rule.label
        label.present? ? " (#{label})" : ""
      end

      def restore(snapshot)
        Parry.with_redis do |redis|
          redis.del(Parry.store.rules_key)
          snapshot.each { |id, json| redis.hset(Parry.store.rules_key, id, json) }
          redis.incr(Parry.store.version_key)
        end
      end

      def failure(message)
        Result.new(imported: 0, errors: [message], replaced: false)
      end
    end
  end
end
