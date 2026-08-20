# frozen_string_literal: true

class HomeController < ActionController::Base
  def index
    render plain: "hello"
  end
end
