## [Unreleased]

- Paginate the blocked hosts page, 50 at a time.

- Export and import rules as JSON, from the GUI or through `Parry::RuleTransfer`.

## [0.1.0] - 2026-08-20

- Initial release: a mountable Rails engine with a GUI for Rack::Attack.
  Manage honeypot, blocklist, safelist and throttle rules stored in Redis, see the hosts that were blocked,
  throttled or caught, and unblock them. Honeypots match their path by prefix or by regular expression.
