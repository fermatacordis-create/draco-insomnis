# frozen_string_literal: true

# The shared firewall cases (tests/vectors/waf.json): PHP, JavaScript, Python, Go and Ruby must agree.
require 'json'
require 'minitest/autorun'
require_relative '../lib/draco_insomnis/waf'

class TestWafVectors < Minitest::Test
  VECTORS = JSON.parse(File.read(File.expand_path('../../tests/vectors/waf.json', __dir__)))

  def run_case(req)
    DracoInsomnis::Waf.inspect_request(path: req['path'] || '', query: req['query'] || '',
                                       params: req['params'] || [], user_agent: req['userAgent'] || '')
  end

  def test_attacks_get_the_same_rule
    VECTORS['attacks'].each { |c| assert_equal c['rule'], run_case(c['request']), c['name'] }
  end

  def test_ordinary_requests_pass
    VECTORS['ordinary'].each { |c| assert_nil run_case(c['request']), c['name'] }
  end

  def test_anchors_are_whole_string_like_php
    # With line anchors, "/x\n.env" would look like a probe in Ruby but not in PHP.
    assert_nil DracoInsomnis::Waf.inspect_request(path: "/.env\n/page")
    assert_equal 'probe', DracoInsomnis::Waf.inspect_request(path: '/.env')
  end
end
