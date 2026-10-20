# frozen_string_literal: true

require "bundler/gem_tasks"
require "minitest/test_task"

# The same suite runs against every storage backend. `rake test` uses SQLite
# and needs no services; the others need `docker compose up -d`.
TEST_BACKENDS = %w[sqlite redis postgres mysql].freeze

Minitest::TestTask.create do |t|
  t.test_globs = ["test/**/*_test.rb"]
end

TEST_BACKENDS.each do |backend|
  Minitest::TestTask.create("test:#{backend}") do |t|
    t.test_globs = ["test/**/*_test.rb"]
    t.test_prelude = %(ENV["PARRY_TEST_BACKEND"] = "#{backend}")
  end
end

desc "Run the tests against every backend (#{TEST_BACKENDS.join(", ")})"
task "test:all" => TEST_BACKENDS.map { |backend| "test:#{backend}" }

require "standard/rake"

task default: %i[test:all standard]
