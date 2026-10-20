# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in parry.gemspec
gemspec

gem "irb"
gem "rake", "~> 13.0"

gem "minitest", "~> 5.16"

gem "standard", "~> 1.3"

group :test do
  gem "rails", ">= 7.1"
  gem "rack-test"
  gem "puma"

  # Every storage backend runs the same suite; see the Rakefile.
  gem "redis", ">= 4.2"
  gem "sqlite3", ">= 1.4"
  gem "pg"
  gem "trilogy"
end
