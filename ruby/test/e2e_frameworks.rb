# frozen_string_literal: true

# The middleware inside real Rails and Sinatra, served by Puma.
# Needs: gem install rails sinatra puma rackup. Run: ruby -Ilib test/e2e_frameworks.rb
require 'logger'
require 'net/http'
require 'uri'
require 'rails'
require 'action_controller/railtie'
require 'sinatra/base'

require 'puma'
begin
  require 'draco_insomnis' # the installed gem, as a user has it
rescue LoadError
  require_relative '../lib/draco_insomnis'
end

ASKED = Hash.new { |h, k| h[k] = [] }
SECRET = 'owner-secret-0123456789'

def draco_options(name)
  { waf: 'block', headers: true, resolver: nil, review: { secret: SECRET }, on_review: ->(r) { ASKED[name] << r.email } }
end

class RailsApp < Rails::Application
  config.eager_load = false
  config.logger = Logger.new(nil)
  config.secret_key_base = 'x' * 64
  config.hosts.clear
  config.middleware.insert_before 0, DracoInsomnis::Rack, **draco_options('rails')
  routes.append do
    root 'pages#home'
    get '/own' => 'pages#own'
    post '/echo' => 'pages#echo'
  end
end

class PagesController < ActionController::Base
  skip_forgery_protection
  def home = render(plain: 'page')

  def own
    response.set_header('X-Frame-Options', 'DENY')
    render plain: 'own'
  end

  def echo = render(plain: "name=#{params[:name]}")
end
RailsApp.initialize!

class SinatraApp < Sinatra::Base
  use DracoInsomnis::Rack, **draco_options('sinatra')
  set :protection, false
  get('/') { 'page' }
  get('/own') do
    headers 'X-Frame-Options' => 'DENY'
    'own'
  end
  post('/echo') { "name=#{params['name']}" }
end

def serve(app)
  server = TCPServer.new('127.0.0.1', 0)
  port = server.addr[1]
  server.close
  puma = Puma::Server.new(app, nil, min_threads: 1, max_threads: 4)
  puma.add_tcp_listener("127.0.0.1", port)
  puma.run
  60.times do
    break if (Net::HTTP.get_response(URI("http://127.0.0.1:#{port}/")) rescue nil)

    sleep 0.2
  end
  port
end

$fails = 0
def check(name, ok)
  puts "#{ok ? 'ok  ' : 'FAIL'} - #{name}"
  $fails += 1 unless ok
end

UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36'
ATTACK = '/search?q=1%27%20union%20select%20password%20from%20users--%20'

def call(port, path, method: 'GET', body: nil, type: nil)
  http = Net::HTTP.new('127.0.0.1', port)
  req = method == 'POST' ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
  req['User-Agent'] = UA
  if body
    req['Content-Type'] = type
    req.body = body
  end
  http.request(req)
end

{ 'rails' => RailsApp, 'sinatra' => SinatraApp }.each do |name, app|
  port = serve(app)
  res = call(port, '/')
  check "#{name}: an ordinary page passes", res.code == '200'
  check "#{name}: security headers", res['x-content-type-options'] == 'nosniff'
  check "#{name}: the app's own header wins", call(port, '/own')['x-frame-options'] == 'DENY'
  page = call(port, ATTACK)
  check "#{name}: SQL injection gets 403", page.code == '403'
  check "#{name}: the page never names the rule", !page.body.include?('sqli')
  check "#{name}: .env probe gets 403", call(port, '/.env').code == '403'
  check "#{name}: a posted form is inspected",
        call(port, '/contact', method: 'POST', body: URI.encode_www_form(message: "x'; DROP TABLE users; --"), type: 'application/x-www-form-urlencoded').code == '403'
  check "#{name}: a JSON body is inspected",
        call(port, '/api', method: 'POST', body: %({"q": "' OR '1'='1"}), type: 'application/json').code == '403'
  echo = call(port, '/echo', method: 'POST', body: 'name=Ana', type: 'application/x-www-form-urlencoded')
  check "#{name}: the app still reads the body", echo.code == '200' && echo.body == 'name=Ana'
  fields = page.body.scan(/<input type="hidden" name="([a-z_]+)" value="([^"]*)">/).to_h
  fields.merge!('draco_email' => 'ana@example.org', 'draco_message' => 'I was searching', 'draco_website' => '')
  thanks = call(port, ATTACK, method: 'POST', body: URI.encode_www_form(fields), type: 'application/x-www-form-urlencoded')
  check "#{name}: the review request is thanked", thanks.code == '200' && thanks.body.include?('Request sent')
  check "#{name}: and reaches the owner", ASKED[name] == ['ana@example.org']
end

puts
puts $fails.zero? ? 'all framework checks passed' : "#{$fails} check(s) failed"
exit($fails.zero? ? 0 : 1)
