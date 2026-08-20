# frozen_string_literal: true

module Parry
  class ApplicationController < ActionController::Base
    protect_from_forgery with: :exception
    layout "parry/application"
  end
end
