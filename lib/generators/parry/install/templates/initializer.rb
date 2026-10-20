# frozen_string_literal: true

Parry.configure do |config|
  # Where Parry keeps its rules, caught hosts and blocked hosts:
  # :active_record (the tables from db/migrate/*_create_parry_tables.rb) or :redis (the default).
  config.backend = :active_record

  # Keep Parry's tables in a database of their own (an entry in config/database.yml).
  # Generate the migration with `rails generate parry:install --database=parry`.
  # config.connects_to = {database: {writing: :parry}}

  # Seconds a process trusts the rules version it last read before checking again.
  # config.version_cache_ttl = 2

  # Trim the blocked hosts table after this many records, or this many seconds.
  # config.tracker_trim_every = 1_000
  # config.tracker_trim_interval = 60

  # Write a given address to the blocked hosts table at most once per N seconds.
  # config.tracker_write_interval = 5

  # How many blocked hosts to keep.
  # config.max_tracked_hosts = 1_000
end
