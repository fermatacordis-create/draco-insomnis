# frozen_string_literal: true

# The engine without a server: the same behaviour the PHP, JavaScript, Python and Go tests check.
require 'json'
require 'socket'
require 'tmpdir'
require 'minitest/autorun'
require_relative '../lib/draco_insomnis'

class TestCore < Minitest::Test
  include DracoInsomnis
  NOW = 1_800_000_000.0
  ROOT = File.expand_path('../..', __dir__)

  def gate(**opts)
    Gatekeeper.new(resolver: nil, now: -> { NOW }, **opts)
  end

  def req(**kw) = Request.new(user_agent: 'Mozilla/5.0 Chrome/131.0', remote_addr: '198.51.100.20', **kw)

  def attack(**kw) = req(query: '../../etc/passwd', params: ['../../etc/passwd'], **kw)

  def hidden(html) = html.scan(/<input type="hidden" name="([a-z_]+)" value="([^"]*)">/).to_h

  # A tiny HTTP server answering every GET with the body the block returns.
  def serve
    server = TCPServer.new('127.0.0.1', 0)
    thread = Thread.new do
      loop do
        client = server.accept
        head = +''
        while (line = client.gets) && line != "\r\n"
          head << line
        end
        body = yield(head).b
        client.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
        client.close
      rescue IOError, SystemCallError
        break
      end
    end
    [server, thread, "http://127.0.0.1:#{server.addr[1]}"]
  end

  def test_addresses_like_php
    refute Net.ip?('01.2.3.4')
    refute Net.ip?('fe80::1%eth0')
    assert_equal '2001:db8:1:2::/64', Net.network('2001:db8:1:2:3:4:5:6')
    assert Blocks.valid_net?('203.0.113.0/24')
    refute Blocks.valid_net?('10.0.0.0/8')
    g = gate(proxy: 'xff')
    assert_equal '203.0.113.5', g.ip(req(remote_addr: '203.0.113.5', forwarded_for: '1.2.3.4'))
    assert_equal '198.51.100.7', g.ip(req(remote_addr: '10.0.0.2', forwarded_for: '1.2.3.4, 198.51.100.7, 10.0.0.9'))
  end

  def test_review_signatures_like_php
    v = JSON.parse(File.read("#{ROOT}/tests/vectors/review.json"))
    v['cases'].each do |c|
      assert_equal c['sealed'], Review.seal(v['secret'], c['ip'], c['ts'].to_s, c['rule'])
      assert_equal c['opened'], Review.open_sealed(v['secret'], c['ip'], c['ts'].to_s, c['sealed'])
      assert_equal c['sig'], Review.sign(v['secret'], c['ip'], c['rule'], c['ts'].to_s)
    end
  end

  def test_review_flow_and_limits
    asked = []
    g = gate(waf: 'block', review: { secret: 'owner-secret-0123456789' }, on_review: ->(r) { asked << r })
    status, _, body = g.render(g.decide(attack))
    assert_equal 403, status
    assert_includes body, 'Ask for a review'
    refute_includes body, 'traversal'
    fields = hidden(body).merge('draco_email' => 'Ana@Example.org', 'draco_message' => 'I was <b>reading</b>', 'draco_website' => '')
    5.times { assert_equal 200, g.decide(req(method: 'POST', form: fields)).status }
    assert_equal 3, asked.size
    assert_equal ['ana@example.org', 'I was reading', 'traversal'], [asked[0].email, asked[0].message, asked[0].rule]
    other = []
    g2 = gate(waf: 'block', review: { secret: 'owner-secret-0123456789' }, on_review: ->(r) { other << r })
    g2.decide(req(method: 'POST', form: fields.merge('draco_sig' => '0' * 64)))
    g2.decide(req(method: 'POST', form: fields, remote_addr: '203.0.113.7'))
    assert_empty other
  end

  def test_firewall_blocks_and_pace
    seen = []
    g = gate(waf: 'block', on_event: ->(e) { seen << e.endpoint })
    assert_nil g.decide(req(query: 'q=european union select committee', params: ['european union select committee']))
    assert_equal 'traversal', g.decide(attack).why
    assert_equal 'probe', g.decide(req(path: '/.env')).why
    4.times { g.decide(attack) }
    assert g.blocks.blocked?('198.51.100.20', NOW)
    assert_nil g.decide(req)
    assert_equal 'blocked', g.decide(req(method: 'POST', path: '/contact')).why
    assert_equal %w[waf:traversal waf:probe], seen.first(2)
    assert_nil gate(waf: 'block', admin_ips: ['198.51.100.20']).decide(attack)
    assert_nil gate(waf: 'block', except: ['webhooks']).decide(attack(path: '/webhooks/stripe'))
    p = gate(waf: 'off', pace: 'block', rate_ip: 10)
    answers = Array.new(12) { p.decide(req(accept: 'text/html')) }
    assert_equal [nil] * 10, answers.first(10)
    assert_equal 429, answers[10].status
    assert_nil p.decide(req(accept: 'application/json'))
  end

  def geo_fixture(built = '20261113')
    v4 = [%w[0.0.0.0 --], %w[1.0.0.0 AU], %w[1.0.1.0 CN], %w[1.0.4.0 --], %w[203.0.113.0 ES], %w[203.0.114.0 --]]
    v6 = [%w[:: --], %w[2a00:: ES], %w[2a01:: --]]
    "DRGEO1#{built}".b + [v4.size, v6.size].pack('NN') + (v4 + v6).map { |ip, cc| Net.to_bytes(ip) + cc.b }.join.b
  end

  def test_geo_like_geo_php
    Dir.mktmpdir do |d|
      File.binwrite("#{d}/g.bin", geo_fixture)
      geo = GeoFile.new("#{d}/g.bin", update: false)
      { '1.0.0.200' => 'AU', '1.0.3.255' => 'CN', '1.0.4.0' => nil, '::ffff:203.0.113.10' => 'ES',
        '2a00:1450::1' => 'ES', '2a01::1' => nil, 'x' => nil }.each { |ip, want| want.nil? ? assert_nil(geo.country(ip)) : assert_equal(want, geo.country(ip)) }
      assert_equal '20261113', geo.built
      g = gate(waf: 'block', geo: { mode: 'block', countries: ['CN'], action: 'block', lookup: geo })
      assert_equal 'geo', g.decide(req(path: '/login', remote_addr: '1.0.2.3')).why
      assert_nil g.decide(req(remote_addr: '1.0.2.3'))
      geo.close
    end
  end

  def test_crowdsec_bridge
    assert_equal 14_381, CrowdSec.seconds('3h59m40.5s')
    assert_equal 0, CrowdSec.seconds('-3s')
    answer = { 'new' => [{ 'type' => 'ban', 'value' => '198.51.100.66', 'duration' => '4h', 'scenario' => 'crowdsecurity/http-probing' },
                         { 'type' => 'ban', 'value' => '203.0.113.0/24', 'duration' => '1h' },
                         { 'type' => 'ban', 'value' => '10.0.0.0/8', 'duration' => '1h' },
                         { 'type' => 'ban', 'value' => '192.0.2.1', 'duration' => '4h' },
                         { 'type' => 'captcha', 'value' => '198.51.100.67', 'duration' => '4h' }], 'deleted' => nil }
    asked = []
    server, thread, url = serve do |head|
      asked << head
      JSON.generate(answer)
    end
    g = gate(waf: 'block', admin_ips: ['192.0.2.1'], crowdsec: { url: url, api_key: 'k3y' })
    g.blocks.add('203.0.113.200', 7, 'Manual', now: NOW)
    assert_equal({ 'added' => 2, 'removed' => 0, 'error' => '' }, g.crowdsec.sync)
    assert_match(/startup=true&scopes=ip,range/, asked[0])
    assert_match(/X-Api-Key: k3y/i, asked[0])
    assert_equal 'blocked', g.decide(req(path: '/login', remote_addr: '198.51.100.66')).why
    assert_equal 'blocked', g.decide(req(method: 'POST', remote_addr: '203.0.113.9')).why
    assert_nil g.decide(req(path: '/login', remote_addr: '10.1.2.3'))
    answer = { 'new' => [], 'deleted' => [{ 'value' => '198.51.100.66' }, { 'value' => '203.0.113.200' }] }
    assert_equal 1, g.crowdsec.sync['removed']
    assert g.blocks.blocked?('203.0.113.200', NOW)
    refute g.blocks.blocked?('198.51.100.66', NOW)
    line = JSON.parse(CrowdSec.line(Event.new(time: 1_800_000_000, ip: '198.51.100.9', endpoint: 'waf:sqli', verdict: 'bot',
                                              reasons: ['waf_sqli'], user_agent: 'curl/8'), 'shop.example'))
    assert_equal({ 'time' => '2027-01-15T08:00:00Z', 'ip' => '198.51.100.9', 'host' => 'shop.example', 'endpoint' => 'waf:sqli',
                   'verdict' => 'bot', 'reasons' => 'waf_sqli', 'user_agent' => 'curl/8' }, line)
  ensure
    server&.close
    thread&.kill
  end

  def test_rack_middleware
    asked = []
    app = lambda do |env|
      headers = { 'content-type' => 'text/plain' }
      headers['x-frame-options'] = 'DENY' if env['PATH_INFO'] == '/own'
      body = env['REQUEST_METHOD'] == 'POST' ? "name=#{URI.decode_www_form(env['rack.input'].read).to_h['name']}" : 'page'
      [200, headers, [body]]
    end
    mw = DracoInsomnis::Rack.new(app, waf: 'block', headers: true, resolver: nil, review: { secret: 'owner-secret-0123456789' },
                                      on_review: ->(r) { asked << r.email })
    env = lambda do |path, method = 'GET', body = nil, type = nil|
      e = { 'REQUEST_METHOD' => method, 'PATH_INFO' => path.split('?')[0], 'QUERY_STRING' => path.split('?')[1].to_s,
            'REMOTE_ADDR' => '198.51.100.30', 'HTTP_USER_AGENT' => 'Mozilla/5.0 Chrome/131.0', 'rack.url_scheme' => 'http',
            'rack.input' => StringIO.new(body.to_s) }
      e.merge!('CONTENT_TYPE' => type, 'CONTENT_LENGTH' => body.bytesize.to_s) if body
      e
    end
    status, headers, = mw.call(env.call('/'))
    assert_equal [200, 'nosniff'], [status, headers['x-content-type-options']]
    assert_equal 'DENY', mw.call(env.call('/own'))[1]['x-frame-options']
    status, _, body = mw.call(env.call('/search?q=1%27%20union%20select%20password%20from%20users--%20'))
    assert_equal 403, status
    refute_includes body.join, 'sqli'
    assert_equal 403, mw.call(env.call('/contact', 'POST', URI.encode_www_form(message: "x'; DROP TABLE users; --"), 'application/x-www-form-urlencoded'))[0]
    assert_equal 403, mw.call(env.call('/api', 'POST', %({"q": "' OR '1'='1"}), 'application/json'))[0]
    assert_equal ['name=Ana'], mw.call(env.call('/echo', 'POST', 'name=Ana', 'application/x-www-form-urlencoded'))[2]
    form = URI.encode_www_form(hidden(body.join).merge('draco_email' => 'ana@example.org', 'draco_message' => 'hi', 'draco_website' => ''))
    assert_equal 200, mw.call(env.call('/search', 'POST', form, 'application/x-www-form-urlencoded'))[0]
    assert_equal ['ana@example.org'], asked
  end
end
