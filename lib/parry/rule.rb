# frozen_string_literal: true

require "ipaddr"
require "json"
require "securerandom"
require "active_model"

module Parry
  class Rule
    include ActiveModel::Model
    include ActiveModel::Attributes

    KINDS = %w[honeypot blocklist safelist throttle].freeze
    IP_KINDS = %w[blocklist safelist].freeze
    PATH_MATCHES = %w[prefix regex].freeze

    attribute :id, :string
    attribute :kind, :string, default: "honeypot"
    attribute :value, :string
    attribute :name, :string
    attribute :limit, :integer
    attribute :period, :integer
    attribute :path, :string
    attribute :path_match, :string, default: "prefix"
    attribute :created_at, :integer

    attr_accessor :persisted

    validates :kind, inclusion: {in: KINDS, message: "is not a valid rule type"}
    validates :value, presence: true, if: :ip_rule?
    validate :value_is_an_ip_or_cidr, if: -> { ip_rule? && value.present? }
    validates :name, presence: true, if: :throttle?
    validates :limit, numericality: {only_integer: true, greater_than: 0}, if: :throttle?
    validates :period, numericality: {only_integer: true, greater_than: 0}, if: :throttle?
    validate :name_is_unique_among_throttles, if: -> { throttle? && name.present? }
    validates :path, presence: true, if: :honeypot?
    validates :path_match, inclusion: {in: PATH_MATCHES, message: "is not a valid way to match a path"},
      if: :honeypot?
    validate :path_is_absolute, if: -> { honeypot? && prefix_match? && path.present? }
    validate :path_is_a_valid_regexp, if: -> { honeypot? && regex_match? && path.present? }

    class << self
      def from_json(json)
        attrs = JSON.parse(json)
        rule = new(attrs.slice(*attribute_names))
        rule.persisted = true
        rule
      rescue JSON::ParserError
        nil
      end

      def kinds
        KINDS
      end
    end

    def ip_rule?
      IP_KINDS.include?(kind)
    end

    def throttle?
      kind == "throttle"
    end

    def honeypot?
      kind == "honeypot"
    end

    def regex_match?
      honeypot? && path_match.to_s == "regex"
    end

    def prefix_match?
      !regex_match?
    end

    def persisted?
      !!persisted
    end

    def to_key
      id ? [id] : nil
    end

    def to_param
      id
    end

    def label
      return name if name.present?
      return value if value.present?

      path.to_s
    end

    def created_at_time
      Time.at(created_at) if created_at
    end

    def matches_ip?(ip)
      range = ip_range
      return false if range.nil? || ip.nil? || ip.to_s.empty?

      range.include?(IPAddr.new(ip.to_s))
    rescue IPAddr::Error
      false
    end

    def matches_path?(candidate)
      return false if path.to_s.empty? || candidate.nil?

      if regex_match?
        matcher = path_regexp
        !matcher.nil? && matcher.match?(candidate.to_s)
      else
        candidate.to_s.start_with?(path)
      end
    rescue Regexp::TimeoutError
      # A bad pattern shouldn't hurt the request.
      Parry.logger.error("[parry] the regex of rule #{id} timed out matching #{candidate}")
      false
    end

    def path_regexp
      return @path_regexp if defined?(@path_regexp)

      @path_regexp = begin
        Regexp.new(path.to_s, timeout: Parry.config.regex_timeout) if regex_match? && path.present?
      rescue RegexpError
        nil
      end
    end

    def ip_range
      return @ip_range if defined?(@ip_range)

      @ip_range = begin
        IPAddr.new(value.to_s) if ip_rule? && value.present?
      rescue IPAddr::Error
        nil
      end
    end

    def normalize!
      self.value = value.strip if value.is_a?(String)
      self.name = name.strip if name.is_a?(String)
      self.path = path.strip.presence if path.is_a?(String)
      self.path_match = "prefix" unless PATH_MATCHES.include?(path_match)

      if throttle?
        self.value = nil
        self.path_match = "prefix"
      elsif honeypot?
        self.value = nil
        self.limit = nil
        self.period = nil
      else
        self.limit = nil
        self.period = nil
        self.path = nil
        self.path_match = "prefix"
      end

      remove_instance_variable(:@ip_range) if defined?(@ip_range)
      remove_instance_variable(:@path_regexp) if defined?(@path_regexp)
      self
    end

    def to_h
      attributes.symbolize_keys
    end

    def to_json(*args)
      to_h.to_json(*args)
    end

    private

    def value_is_an_ip_or_cidr
      IPAddr.new(value.to_s)
    rescue IPAddr::Error
      errors.add(:value, "is not a valid IP address or CIDR range")
    end

    def path_is_absolute
      errors.add(:path, "has to start with /") unless path.to_s.start_with?("/")
    end

    def path_is_a_valid_regexp
      Regexp.new(path.to_s)
    rescue RegexpError => e
      errors.add(:path, "is not a valid regular expression (#{e.message.lines.first.to_s.strip})")
    end

    def name_is_unique_among_throttles
      taken = Parry.store.where(kind: "throttle").any? { |other| other.name == name && other.id != id }
      errors.add(:name, "is already used by another throttle") if taken
    rescue => e
      Parry.logger.warn("[parry] could not verify throttle name uniqueness: #{e.class}: #{e.message}")
    end
  end
end
