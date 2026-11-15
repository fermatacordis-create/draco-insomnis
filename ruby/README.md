# Draco Insomnis for Ruby

The Draco Insomnis firewall as **Rack middleware**, with **no dependencies**: Rails, Sinatra, Hanami,
Roda and any Rack app. Same signatures and limits as the WordPress, CMS, server, JavaScript, Python
and Go editions; the Ruby engine runs the same shared test cases (`tests/vectors`).

```ruby
# Rails: config/application.rb
config.middleware.insert_before 0, DracoInsomnis::Rack, waf: 'block', pace: 'block', headers: true, logger: Rails.logger

# Sinatra, Roda, Hanami: config.ru
use DracoInsomnis::Rack, waf: 'block'
```

Ruby 3.1 or newer. `gem install ./draco-insomnis-X.Y.Z.gem` (from the release).

What it does, in this order: blocked addresses may read but not post or open sensitive pages
(Devise's `/users/sign_in` and `/users/sign_up` included); the country filter (behind Cloudflare from
its header, otherwise `geo: { lookup: DracoInsomnis::GeoFile.new(path) }`); the firewall signatures
(log or block; 5 attacks in 10 minutes block the address for 7 days); the anti-copy pace limit (HTML
pages only; Google, Bing, Apple and Yandex once the reverse DNS proves them). Forms and JSON bodies
up to 64 KB are read once and put back. Security headers never replace the app's own. If Draco itself
fails, the request goes through.

| Option | Default | |
| --- | --- | --- |
| `waf` | `'log'` | `'off'`, `'log'` or `'block'` |
| `pace` | `'off'` | `'off'`, `'log'` or `'block'`; `rate_ip`, `rate_net` (at least 10) |
| `proxy`, `trusted_proxies` | connection | `'cf'` or `'xff'`, and who may set them |
| `admin_ips`, `except`, `sensitive` | | never inspected; path prefixes never inspected; extra sensitive endings |
| `headers`, `hsts` | off | nosniff, frames, referrer, permissions; HSTS over HTTPS |
| `geo` | off | `{ mode: 'block' or 'allow', countries: [...], action: 'log' or 'block', scope: 'sensitive' or 'site', lookup: GeoFile }` |
| `review` | off | `{ secret: '16+ characters' }`; requests reach `on_review` (and `logger`) |
| `crowdsec` | off | `{ url: 'http://127.0.0.1:8080', api_key: '...' }` |
| `store` | memory | anything with `bump`, `get`, `set`, `delete`; same keys as the other editions |
| `logger`, `on_event`, `on_review` | | evidence and review requests |

Tests: `ruby -Ilib -e 'Dir["test/test_*.rb"].each { |f| require_relative f }'` (the engine and the shared
vectors), and `ruby -Ilib test/e2e_frameworks.rb` with `rails sinatra puma` installed (real Rails and
Sinatra on Puma).
