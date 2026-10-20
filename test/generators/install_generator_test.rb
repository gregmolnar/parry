# frozen_string_literal: true

require "test_helper"
require "rails/generators/test_case"
require "generators/parry/install/install_generator"

module Parry
  class InstallGeneratorTest < Rails::Generators::TestCase
    tests Parry::Generators::InstallGenerator
    destination File.expand_path("../../tmp/generators", __dir__)
    setup :prepare_destination

    test "it writes the migration and an initializer" do
      run_generator

      assert_migration "db/migrate/create_parry_tables.rb" do |migration|
        assert_match(/class CreateParryTables < ActiveRecord::Migration\[\d+\.\d+\]/, migration)
        %w[parry_rules parry_versions parry_blocked_hosts parry_caught_hosts].each do |table|
          assert_match(/create_table :#{table}/, migration)
        end
        assert_match(/add_index :parry_blocked_hosts, :ip, unique: true/, migration)
        assert_match(/add_index :parry_blocked_hosts, :last_seen/, migration)
        assert_match(/add_index :parry_caught_hosts, :ip, unique: true/, migration)
      end

      assert_file "config/initializers/parry.rb", /Parry\.configure/
    end

    test "an existing initializer is left alone" do
      FileUtils.mkdir_p(File.join(destination_root, "config/initializers"))
      File.write(File.join(destination_root, "config/initializers/parry.rb"), "# mine\n")

      run_generator

      assert_file "config/initializers/parry.rb", "# mine\n"
    end
  end
end
