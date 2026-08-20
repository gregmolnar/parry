# frozen_string_literal: true

require "rails"
require "action_controller/railtie"
require "rack/attack"

require "parry"

module Dummy
  class Application < Rails::Application
    config.root = File.expand_path("..", __dir__)
    config.eager_load = false
    config.secret_key_base = "parry-dummy-application-secret-key-base"
    config.logger = Logger.new(IO::NULL)
    config.hosts.clear

    config.middleware.use Rack::Attack
  end
end
