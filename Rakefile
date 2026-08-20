# frozen_string_literal: true

require "bundler/gem_tasks"
require "minitest/test_task"

Minitest::TestTask.create do |t|
  t.test_globs = ["test/**/*_test.rb"]
end

require "standard/rake"

task default: %i[test standard]
