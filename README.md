# Parry

Parry is a mountable Rails engine that puts a GUI in front of [Rack::Attack](https://github.com/rack/rack-attack).

Rack::Attack rules normally live in an initializer, so changing them means a deploy. Parry keeps its rules in
Redis instead and applies them to every application process as soon as you save them:

- manage **blocklists**, **safelists**, **throttles** and **honeypots** from a web page
- see the hosts that were **blocked or throttled**, with hit counts and the rule they matched
- **unblock** a host: the blocklist rules covering it are deleted and its throttle counters are reset

Parry has no opinion about authentication - mount it behind whatever your application already uses.

## Installation

```ruby
# Gemfile
gem "parry"
```

Parry depends on `rack-attack` and `redis`. Make sure Rack::Attack itself is set up in your application:

```ruby
# config/application.rb
config.middleware.use Rack::Attack
```

```ruby
# config/initializers/rack_attack.rb
# Rack::Attack needs a shared, incrementable cache store. Redis is a good fit.
Rack::Attack.cache.store = ActiveSupport::Cache::RedisCacheStore.new(url: ENV["REDIS_URL"])
```

Then mount the engine:

```ruby
# config/routes.rb
mount Parry::Engine => "/parry"
```

## Authentication

The engine is deliberately unauthenticated, so restrict it when you mount it. With Devise:

```ruby
authenticate :user, ->(user) { user.admin? } do
  mount Parry::Engine => "/parry"
end
```

With HTTP basic auth:

```ruby
Parry::Engine.middleware.use(Rack::Auth::Basic) do |username, password|
  ActiveSupport::SecurityUtils.secure_compare(username, ENV.fetch("PARRY_USER")) &
    ActiveSupport::SecurityUtils.secure_compare(password, ENV.fetch("PARRY_PASSWORD"))
end

mount Parry::Engine => "/parry"
```

Or with a route constraint:

```ruby
constraints ->(request) { request.session[:admin] } do
  mount Parry::Engine => "/parry"
end
```

## Configuration

```ruby
# config/initializers/parry.rb
Parry.configure do |config|
  # Redis client. Defaults to Redis.new(url: ENV["PARRY_REDIS_URL"] || ENV["REDIS_URL"]).
  # A ConnectionPool works too - anything that responds to #with.
  config.redis = Redis.new(url: ENV["PARRY_REDIS_URL"])

  # Prefix for every key Parry writes. Default: "parry".
  config.key_prefix = "parry"

  # Register the Rack::Attack hooks on boot. Default: true.
  # Set to false to call Parry.install! yourself.
  config.auto_install = true

  # Record blocked and throttled requests for the "Blocked hosts" page. Default: true.
  config.track_events = true

  # How many hosts that page keeps, oldest dropped first. Default: 1000.
  # The page itself lists them 50 at a time.
  config.max_tracked_hosts = 1_000

  # Seconds a honeypot regex may spend on one path before it is abandoned.
  # Default: 0.05.
  config.regex_timeout = 0.05
end
```

## Redis persistence

Parry's rules and the hosts its honeypots caught are **data, not cache**. If the Redis holding them loses its
contents, your rules are gone and every host you blocked is free again. Two ways that happens:

**A Redis container without a volume.** Everything lives in the container's writable layer, so anything that
recreates the container - a redeploy, `docker compose up --force-recreate`, a host rebuild - wipes it. Give it a
volume and turn on the append-only file:

```yaml
services:
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - ./tmp/redis:/data
```

With Kamal, run Redis as an accessory with a directory of its own:

```yaml
# config/deploy.yml
accessories:
  redis:
    image: redis:7-alpine
    host: 203.0.113.10
    cmd: redis-server --appendonly yes
    directories:
      - data:/data
```

`directories` bind-mounts a directory on the host into the container, so the data outlives any container that
gets replaced. Without it the accessory keeps everything inside the container, and the first
`kamal accessory reboot redis` - or anything else that recreates it - starts from an empty database.

**A Redis used as a cache.** With a `maxmemory` limit and an eviction policy like `allkeys-lru`, Redis quietly
drops keys when it fills up, and it does not exempt yours. Either run the instance with `noeviction`, or point
Parry somewhere else with `PARRY_REDIS_URL` - a separate database on the same server is enough:

```ruby
Parry.configure do |config|
  config.redis = Redis.new(url: ENV.fetch("PARRY_REDIS_URL"))
end
```

To check what a running server is doing:

```sh
redis-cli config get appendonly
redis-cli config get maxmemory-policy
```

## Rule types

| Type | Effect |
| --- | --- |
| Blocklist | Requests from the IP or CIDR range get `403 Forbidden` |
| Safelist | Requests from the IP or CIDR range skip every blocklist, throttle and honeypot |
| Throttle | More than *limit* requests per *period* seconds from one IP get `429 Too Many Requests`, optionally only under a path prefix |
| Honeypot | Requesting the path - by prefix or regex - blocklists the host, so all of its later requests get `403 Forbidden` too |

Both IPv4 and IPv6 addresses and ranges are accepted.

### Honeypots

A honeypot turns a path into bait. The first request to it gets a `403`, and the host is blocked everywhere
until you release it:

```
GET /.env  from 203.0.113.9   -> 403, host caught
GET /      from 203.0.113.9   -> 403, still blocked
GET /      from 198.51.100.1  -> 200
```

Point honeypots at paths a real visitor never requests - `/.env`, `/wp-login.php`, `/.git/config` - and they will
catch the scanners probing for them. Caught hosts show up under **Blocked hosts** as `Caught`, together with
the path that caught them, and the Unblock button releases them.

A honeypot matches its path in one of two ways:

**Prefix** (the default) - `/wp-login.php` also catches `/wp-login.php.bak`, and `/admin` catches everything
below `/admin`.

**Regular expression** - one rule can cover a family of probes:

| Pattern | Catches |
| --- | --- |
| `\.(env\|git)` | `/.env`, `/.git/config`, `/config/.env` |
| `\A/(wp-admin\|wp-login)` | `/wp-admin/`, `/wp-login.php` |
| `\.(php\|asp\|aspx)\z` | any request ending in a PHP or ASP extension |

The pattern is ordinary Ruby regex syntax and is **matched anywhere in the path unless you anchor it** with `\A`
or `\z`. Bear in mind the path always starts with `/`, so `\Awp-` never matches anything - you want `\A/wp-`.

Whichever you choose, pick it carefully: anything a legitimate visitor can reach blocks them, so `/` as a prefix
honeypots your entire audience. Safelist your own address before arming a broad one.

Regexes are compiled with a timeout (`config.regex_timeout`, 50ms by default) because they run against every
request path. A pattern that backtracks catastrophically is abandoned and logged rather than allowed to hang the
request, and a pattern that does not compile is rejected by the form.

## Export and import

The rules list has **Export** and **Import** buttons. Export downloads every rule as JSON; import reads that
file back, either adding to the rules already there or replacing them outright.

```json
{
  "format": 1,
  "parry_version": "0.1.0",
  "exported_at": 1787390429,
  "rules": [
    {"id": "3f2a...", "kind": "honeypot", "path": "\\.(env|git)", "path_match": "regex", "name": "Config probe"}
  ]
}
```

Use it to keep a backup of a hand-built rule set, to move rules from staging to production, or to keep the
same honeypots across several applications. Rules keep their ids, so re-importing the same file updates the
rules it already created instead of duplicating them.

**An import is all or nothing.** Every rule in the file is validated as it is applied, and if any one of them is
rejected the whole import is rolled back and each problem is listed - a file with a typo in it can never leave
you with half a rule set. That holds for "replace" too: the rules you have now are only let go once the
replacement is known to be good.

The same thing from a console, if you would rather script it:

```ruby
File.write("rules.json", Parry::RuleTransfer.export_json)

result = Parry::RuleTransfer.import(File.read("rules.json"), replace: true)
result.ok?       # => true
result.imported  # => 3
result.errors    # => []
```

Blocked and caught hosts are deliberately not part of an export - they are a record of what happened on one
server, not configuration.

## How it works

Parry registers exactly one safelist and one blocklist check with Rack::Attack, plus one real
`Rack::Attack.throttle` per throttle rule. Rules are stored in a Redis hash next to a version counter that is
bumped on every write, and caught hosts live in a hash of their own that bumps the same counter.
The safelist check runs on every request and compares that counter against the snapshot
the process is holding, reloading the rules when it changed - so an edit made in one process is picked up by all
of them, at the cost of one Redis `GET` per request.

Rules you define yourself in an initializer keep working; Parry only adds to them.

If Redis is unreachable, Parry logs the error and keeps serving the last snapshot it loaded rather than taking
requests down with it.

## Things worth knowing

- **The rules apply to the GUI too.** A throttle without a path prefix counts your own visits to the Parry pages,
  and if your address ends up blocklisted you will not be able to reach them. Safelisting the address you
  administer from avoids locking yourself out.
- **A caught host stays blocked when you delete the honeypot rule.** The rule is the sensor, the caught host is
  the result: removing the sensor does not vouch for the hosts it already caught. Release them individually from
  the Blocked hosts page.
- **Safelist yourself before arming a broad honeypot.** The safelist check runs first, so a safelisted address can
  never be caught - it is the way back in if a honeypot turns out to cover more than you meant.
- **Unblock only removes Parry's own rules.** Blocklists written in your initializer are static Ruby, so the GUI
  cannot delete them - it reports the throttle counters it reset instead.
- **Unblock clears the current throttle window** for every registered throttle, including throttles your own
  initializer defines, and releases the host from any honeypot. Counters from `Fail2Ban` and `Allow2Ban` are not
  touched.
- **Use a shared cache store.** With the default in-memory store each process counts separately and unblocking
  only affects the process that handled the request.
- **Give Redis a volume.** Rules and caught hosts do not survive a container that gets recreated without one -
  see [Redis persistence](#redis-persistence).

## Development

Parry's test suite runs against a real Redis and a dummy Rails application:

```sh
docker compose up -d   # Redis on port 6380
bin/setup
bundle exec rake       # tests + standard
```

To click through the GUI, boot the dummy application:

```sh
REDIS_URL=redis://127.0.0.1:6380/2 bundle exec puma test/dummy/config.ru -p 3210
# then open http://127.0.0.1:3210/parry
```

## Contributing

Bug reports and pull requests are welcome at https://github.com/gregmolnar/parry.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
