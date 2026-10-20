## [Unreleased]

- Add an ActiveRecord storage backend (PostgreSQL, MySQL, SQLite). Redis stays the default, so existing installs
  need no change. Run `rails generate parry:install` and `rails db:migrate` to switch: the generated initializer
  sets `config.backend = :active_record`.
- `activerecord` is now a dependency. It is only loaded when the ActiveRecord backend is used.
- New options for the ActiveRecord backend: `version_cache_ttl`, `tracker_trim_every`, `tracker_trim_interval`,
  `tracker_write_interval` and `connects_to` (a separate database for Parry's tables).
- Add `Parry.tracker.trim!`.
- To move existing rules from Redis to the database, export them from the GUI, switch backends and import them
  again.

## [0.2.0] - 2026-10-16

- Paginate the blocked hosts page, 50 at a time.

- Export and import rules as JSON, from the GUI or through `Parry::RuleTransfer`.

## [0.1.0] - 2026-08-20

- Initial release: a mountable Rails engine with a GUI for Rack::Attack.
  Manage honeypot, blocklist, safelist and throttle rules stored in Redis, see the hosts that were blocked,
  throttled or caught, and unblock them. Honeypots match their path by prefix or by regular expression.
