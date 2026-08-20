# frozen_string_literal: true

require "rails/engine"

module Parry
  class Engine < ::Rails::Engine
    isolate_namespace Parry

    config.parry = Parry.config

    # Runs after the host application's initializers so a Rack::Attack cache
    # store configured there is already in place.
    initializer "parry.install", after: :load_config_initializers do
      Parry.install! if Parry.config.auto_install
    end
  end
end
