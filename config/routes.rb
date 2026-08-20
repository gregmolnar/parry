# frozen_string_literal: true

Parry::Engine.routes.draw do
  resources :rules, except: [:show] do
    collection do
      get :export
      get :import
      post :import, action: :perform_import, as: :perform_import
    end
  end

  resources :blocked_hosts, only: [:index] do
    collection do
      post :unblock
    end
  end

  root to: "rules#index"
end
