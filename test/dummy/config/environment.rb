# frozen_string_literal: true

require_relative "application"

Rack::Attack.cache.store = ActiveSupport::Cache::RedisCacheStore.new(url: ENV.fetch("REDIS_URL"))

Rails.application.initialize!
