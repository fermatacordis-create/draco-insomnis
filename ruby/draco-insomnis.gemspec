# frozen_string_literal: true

require_relative 'lib/draco_insomnis/version'

Gem::Specification.new do |s|
  s.name = 'draco-insomnis'
  s.version = DracoInsomnis::VERSION
  s.summary = 'Firewall, anti-copy pace, country filter, review requests and CrowdSec for Rack apps (Rails, Sinatra, Hanami, Roda). No dependencies.'
  s.description = 'The Draco Insomnis firewall as Rack middleware, with the same signatures and limits as the WordPress, CMS, ' \
                  'JavaScript, Python and Go editions, checked against the same shared test cases.'
  s.authors = ['Notorius Vision']
  s.license = 'GPL-2.0-or-later'
  s.homepage = 'https://github.com/fermatacordis-create/draco-insomnis'
  s.metadata = {
    'source_code_uri' => 'https://github.com/fermatacordis-create/draco-insomnis/tree/main/ruby',
    'bug_tracker_uri' => 'https://github.com/fermatacordis-create/draco-insomnis/issues',
    'rubygems_mfa_required' => 'true'
  }
  s.required_ruby_version = '>= 3.1'
  s.files = Dir['lib/**/*.rb'] + %w[README.md LICENSE]
  s.require_paths = ['lib']
end
