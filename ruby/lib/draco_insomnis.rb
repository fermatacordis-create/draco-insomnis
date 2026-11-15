# frozen_string_literal: true

# Draco Insomnis for Ruby: the same firewall, block list, country filter, anti-copy pace, review
# requests and CrowdSec bridge as the PHP, JavaScript, Python and Go editions, checked against the
# same shared test cases. Standard library only. As Rack middleware it runs in Rails, Sinatra, Hanami
# and Roda:
#
#   # config/application.rb (Rails)
#   config.middleware.insert_before 0, DracoInsomnis::Rack, waf: 'block', headers: true
#
#   # config.ru (Sinatra, Roda, Hanami…)
#   use DracoInsomnis::Rack, waf: 'block'
require_relative 'draco_insomnis/version'
require_relative 'draco_insomnis/waf'
require_relative 'draco_insomnis/core'
require_relative 'draco_insomnis/gatekeeper'
require_relative 'draco_insomnis/rack'
