# frozen_string_literal: true

require "active_record"

module Parry
  # Base class of the models behind the ActiveRecord backend. They share the
  # host application's connection unless +config.connects_to+ points them at a
  # database of their own:
  #
  #   # config/database.yml has a "parry" entry next to "primary"
  #   Parry.configure do |config|
  #     config.connects_to = {database: {writing: :parry}}
  #   end
  #
  # It lives in lib/, not app/models/, so an application on the Redis backend
  # that never loads ActiveRecord does not trip over it when eager loading.
  class ApplicationRecord < ::ActiveRecord::Base
    self.abstract_class = true

    class << self
      # Hands +config.connects_to+ to ActiveRecord. Runs when the backend is
      # built; calling it again with the same options does nothing.
      def apply_connection_config!(options = Parry.config.connects_to)
        return false if options.nil? || options.empty? || options == @applied_connection_config

        connects_to(**options)
        @applied_connection_config = options
        true
      end
    end
  end

  # The tables written by `rails generate parry:install`. Timestamps are stored
  # as integer epoch seconds, like the rest of Parry, so ActiveRecord's own
  # timestamping is switched off.
  module Records
    class Rule < ApplicationRecord
      self.table_name = "parry_rules"
      self.primary_key = "id"
      self.record_timestamps = false
    end

    # A single row (id 1) holding the counter that is bumped on every write
    # affecting the rule set.
    class Version < ApplicationRecord
      self.table_name = "parry_versions"
      self.record_timestamps = false
    end

    class BlockedHost < ApplicationRecord
      self.table_name = "parry_blocked_hosts"
      self.record_timestamps = false
    end

    class CaughtHost < ApplicationRecord
      self.table_name = "parry_caught_hosts"
      self.record_timestamps = false
    end
  end
end
