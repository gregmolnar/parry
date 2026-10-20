## [Unreleased]

- Add an ActiveRecord storage backend (PostgreSQL, MySQL, SQLite) and make it the default; Redis remains
  available with `config.backend = :redis`. Run `rails generate parry:install` and `rails db:migrate` to create
  the tables.
- The `redis` gem is no longer a dependency. Add it to your Gemfile to keep using the Redis backend; Parry raises
  a clear error if it is missing. `activerecord` is now a dependency.
- New options for the ActiveRecord backend: `version_cache_ttl`, `tracker_trim_every`, `tracker_trim_interval`,
  `tracker_write_interval` and `connects_to` (a separate database for Parry's tables).
- Add `Parry.tracker.trim!`.
- **Upgrading from 0.2.0 with your rules in Redis:** set `config.backend = :redis` and add `gem "redis"`, or
  export your rules from the GUI, switch backends and import them again.

## [0.2.0] - 2026-10-16

- Paginate the blocked hosts page, 50 at a time.

- Export and import rules as JSON, from the GUI or through `Parry::RuleTransfer`.

## [0.1.0] - 2026-08-20

- Initial release: a mountable Rails engine with a GUI for Rack::Attack.
  Manage honeypot, blocklist, safelist and throttle rules stored in Redis, see the hosts that were blocked,
  throttled or caught, and unblock them. Honeypots match their path by prefix or by regular expression.
