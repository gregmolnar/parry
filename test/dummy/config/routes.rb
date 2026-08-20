# frozen_string_literal: true

Rails.application.routes.draw do
  mount Parry::Engine => "/parry"

  get "/login", to: "home#index"
  root to: "home#index"

  # Honeypot paths like /.env do not exist in a real app either; the catch-all
  # keeps a request that was *not* blocked from 404ing and muddying the tests.
  get "/*path", to: "home#index"
end
