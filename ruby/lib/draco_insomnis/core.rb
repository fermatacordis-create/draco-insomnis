# frozen_string_literal: true

require 'json'
require 'openssl'
require 'resolv'
require 'net/http'
require 'cgi'
require 'securerandom'
require 'digest'
require 'fileutils'

module DracoInsomnis
  # Addresses and networks, like src/Core/NetList.php: decimal IPv4 without leading zeros, no zones.
  module Net
    CLOUDFLARE = %w[173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18
                    190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13
                    104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32
                    2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32].freeze
    LOCAL_PROXIES = %w[127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16
                       ::1/128 fc00::/7 fe80::/10].freeze

    module_function

    def v4(value)
      parts = value.split('.', -1)
      return nil unless parts.size == 4

      parts.map do |p|
        return nil unless p.match?(/\A(0|[1-9]\d{0,2})\z/) && p.to_i <= 255

        p.to_i
      end.pack('C4')
    end

    def v6(value)
      return nil if value.include?('%') || !value.match?(/\A[0-9a-f:.]+\z/i)

      halves = value.split('::', -1)
      return nil if halves.size > 2

      words = lambda do |s|
        return [] if s.empty?

        items = s.split(':', -1)
        items.each_with_index.flat_map do |item, i|
          if i == items.size - 1 && item.include?('.')
            b = v4(item) or return nil
            [(b.getbyte(0) << 8) | b.getbyte(1), (b.getbyte(2) << 8) | b.getbyte(3)]
          else
            return nil unless item.match?(/\A[0-9a-f]{1,4}\z/i)

            [item.to_i(16)]
          end
        end
      end
      head = words.call(halves[0])
      tail = halves.size == 2 ? words.call(halves[1]) : []
      return nil if head.nil? || tail.nil?

      missing = 8 - head.size - tail.size
      return nil if halves.size == 2 ? missing < 1 : missing != 0

      (head + [0] * (halves.size == 2 ? missing : 0) + tail).pack('n8')
    end

    # The address as 4 or 16 bytes, or nil.
    def to_bytes(ip)
      v = ip.to_s.strip
      v.include?(':') ? v6(v) : v4(v)
    end

    def ip?(ip) = !to_bytes(ip).nil?

    def from_bytes(b)
      return b.unpack('C4').join('.') if b.bytesize == 4

      w = b.unpack('n8')
      best = -1
      best_len = 0
      i = 0
      while i < 8
        if w[i] != 0
          i += 1
          next
        end
        j = i
        j += 1 while j < 8 && w[j].zero?
        best, best_len = i, j - i if j - i > best_len && j - i >= 2
        i = j
      end
      hex = ->(xs) { xs.map { |x| x.to_s(16) }.join(':') }
      best.negative? ? hex.call(w) : "#{hex.call(w[0...best])}::#{hex.call(w[(best + best_len)..])}"
    end

    def in_net?(cidr, ip)
      base_text, bits_text = cidr.strip.split('/', 2)
      base = to_bytes(base_text)
      addr = to_bytes(ip)
      return false if base.nil? || addr.nil? || base.bytesize != addr.bytesize

      max = base.bytesize * 8
      bits = bits_text&.match?(/\A\d+\z/) ? bits_text.to_i : max
      return false if bits > max

      whole, rest = bits.divmod(8)
      return false if base.byteslice(0, whole) != addr.byteslice(0, whole)
      return true if rest.zero?

      mask = (0xff << (8 - rest)) & 0xff
      (base.getbyte(whole) & mask) == (addr.getbyte(whole) & mask)
    end

    def contains?(nets, ip) = nets.any? { |n| in_net?(n, ip) }

    # Networks and addresses from text or a list: one per line or comma-separated; "#" starts a comment.
    def parse(text)
      lines = text.is_a?(String) ? text.split(/\r\n|\r|\n/) : Array(text)
      lines.flat_map { |l| l.to_s.sub(/#.*/, '').split(/[\s,]+/) }
           .select { |i| !i.empty? && ip?(i.split('/', 2)[0]) }.uniq
    end

    def network(ip)
      b = to_bytes(ip)
      return '' if b.nil?
      return "#{b.unpack('C3').join('.')}.0/24" if b.bytesize == 4

      "#{from_bytes(b.byteslice(0, 8) + ("\0" * 8).b)}/64"
    end

    def unmap(ip) = ip.match?(/\A::ffff:\d+\.\d+\.\d+\.\d+\z/i) ? ip[7..] : ip
  end

  # A line of evidence: the same fields as the PHP events table and the other editions.
  Event = Struct.new(:time, :ip, :remote, :endpoint, :verdict, :reasons, :user_agent, :detail, :email, keyword_init: true)

  # One accepted review request, for the owner.
  ReviewRequest = Struct.new(:time, :ip, :rule, :email, :message, :user_agent, keyword_init: true)

  # Counters, the block list and verified crawlers. Same keys as the JavaScript, Python and Go
  # editions, so one Redis can serve apps in several languages. Thread-safe.
  class MemoryStore
    def initialize(now = -> { Time.now.to_f })
      @items = {}
      @lock = Mutex.new
      @now = now
    end

    def bump(key, ttl)
      @lock.synchronize do
        value, until_ = live(key)
        n = value.nil? ? 1 : value.to_i + 1
        @items[key] = [n.to_s, value.nil? ? @now.call + ttl : until_]
        sweep
        n
      end
    end

    def get(key) = @lock.synchronize { live(key)&.first }

    def set(key, value, ttl)
      @lock.synchronize do
        @items[key] = [value, ttl.zero? ? 0 : @now.call + ttl]
        sweep
      end
    end

    def delete(key) = @lock.synchronize { @items.delete(key) }

    private

    def live(key)
      item = @items[key] or return nil
      if item[1] != 0 && item[1] <= @now.call
        @items.delete(key)
        return nil
      end
      item
    end

    def sweep
      @items.each_key.to_a.each { |k| live(k) } if @items.size >= 50_000
    end
  end

  # The block list on any store: one key per address, one key holding the blocked networks.
  class Blocks
    FOREVER = 253_402_300_799

    def self.valid_net?(cidr)
      m = cidr.strip.match(/\A([0-9a-f.:]+)\/(\d+)\z/i) or return false
      b = Net.to_bytes(m[1]) or return false
      bits = m[2].to_i
      b.bytesize == 16 ? bits.between?(32, 128) : bits.between?(16, 32)
    end

    def initialize(store) = @store = store

    def add(value, days, reason, automatic: false, now: Time.now.to_f)
      until_ = days.zero? ? FOREVER : now.to_i + (days * 86_400)
      write(value, until_, reason, automatic, now, days.zero? ? 0 : days * 86_400)
    end

    def add_until(value, until_, reason, automatic: true, now: Time.now.to_f)
      ttl = (until_ - now).to_i
      ttl.positive? && write(value, until_.to_i, reason, automatic, now, ttl)
    end

    def remove(value, now: Time.now.to_f)
      if value.include?('/')
        @store.set('draco:nets', JSON.generate(nets(now).reject { |n| n['value'] == value }), 0)
      else
        @store.delete("draco:block:#{value}")
      end
    end

    def nets(now = Time.now.to_f)
      JSON.parse(@store.get('draco:nets') || '[]').select { |n| n['until'] > now }
    rescue JSON::ParserError
      []
    end

    def entry(value, now = Time.now.to_f)
      return nets(now).find { |n| n['value'] == value } if value.include?('/')

      raw = @store.get("draco:block:#{value}")
      raw && JSON.parse(raw)
    rescue JSON::ParserError
      nil
    end

    def blocked?(ip, now = Time.now.to_f)
      !@store.get("draco:block:#{ip}").nil? || nets(now).any? { |n| Net.in_net?(n['value'], ip) }
    end

    private

    def write(value, until_, reason, automatic, now, ttl)
      entry = { 'value' => value, 'until' => until_, 'reason' => reason, 'automatic' => automatic }
      if value.include?('/')
        return false unless self.class.valid_net?(value)

        @store.set('draco:nets', JSON.generate(nets(now).reject { |n| n['value'] == value } + [entry]), 0)
      else
        @store.set("draco:block:#{value}", JSON.generate(entry), ttl)
      end
      true
    end
  end

  # "This is a mistake": the review form from the 403 page — the same seals, signatures and limits as
  # src/Core/Review.php (tests/vectors/review.json).
  module Review
    FIELD = 'draco_review'
    EMAIL = %r{\A[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+\z}i

    module_function

    def mac(secret, data) = OpenSSL::HMAC.digest('SHA256', secret, data)

    def clean_rule(rule) = rule.to_s.downcase.gsub(/[^a-z0-9_]/, '')

    def seal(secret, ip, ts, rule)
      plain = clean_rule(rule)[0, 32].b.ljust(32, "\0")
      key = mac(secret, "review-rule|#{ip}|#{ts}")
      plain.bytes.zip(key.bytes).map { |a, b| a ^ b }.pack('C*').unpack1('H*')
    end

    def open_sealed(secret, ip, ts, sealed)
      return '' unless sealed.to_s.match?(/\A[0-9a-f]{64}\z/i)

      key = mac(secret, "review-rule|#{ip}|#{ts}")
      rule = [sealed].pack('H*').bytes.zip(key.bytes).map { |a, b| a ^ b }.pack('C*').sub(/\0+\z/, '')
      rule.match?(/\A[a-z0-9_]*\z/) ? rule : ''
    end

    def sign(secret, ip, rule, ts) = mac(secret, "review|#{ip}|#{rule}|#{ts}").unpack1('H*')

    def form(secret, ip, why, now, t)
      h = ->(s) { CGI.escapeHTML(s.to_s) }
      ts = now.to_i.to_s
      rule = clean_rule(why)
      '<form method="post" action="">' \
        "<input type=\"hidden\" name=\"#{FIELD}\" value=\"1\">" \
        "<input type=\"hidden\" name=\"draco_rule\" value=\"#{h.call(seal(secret, ip, ts, rule))}\">" \
        "<input type=\"hidden\" name=\"draco_ts\" value=\"#{h.call(ts)}\">" \
        "<input type=\"hidden\" name=\"draco_sig\" value=\"#{h.call(sign(secret, ip, rule, ts))}\">" \
        '<p class="hp"><label>Website <input type="text" name="draco_website" tabindex="-1" autocomplete="off"></label></p>' \
        "<label for=\"draco-r-email\">#{h.call(t['review_email'])}</label>" \
        '<input id="draco-r-email" type="email" name="draco_email" required maxlength="190">' \
        "<label for=\"draco-r-msg\">#{h.call(t['review_message'])}</label>" \
        '<textarea id="draco-r-msg" name="draco_message" rows="3" maxlength="500" required></textarea>' \
        "<button type=\"submit\">#{h.call(t['review_button'])}</button></form>"
    end

    def accept(store, secret, ip, user_agent, post, now)
      ts = post['draco_ts'].to_s
      rule = open_sealed(secret, ip, ts, post['draco_rule'].to_s)
      email = post['draco_email'].to_s.strip.downcase
      message = post['draco_message'].to_s.gsub(%r{<(script|style)[^>]*?>.*?</\1>|<[^>]*>}im, '')
                                      .gsub(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/, '').strip[0, 500]
      fresh = ts.match?(/\A\d+\z/) && ts.to_i <= now && now - ts.to_i < 86_400
      sig = post['draco_sig'].to_s
      ok = fresh && sig.bytesize == 64 && OpenSSL.fixed_length_secure_compare(sign(secret, ip, rule, ts), sig) &&
           post['draco_website'].to_s.empty? && email.match?(EMAIL) && email.size <= 190 && !message.empty?
      return nil unless ok

      day = Time.at(now).utc.strftime('%Y%m%d')
      return nil if store.bump("draco:review:ip:#{ip}", 86_400) > 3 || store.bump("draco:review:day:#{day}", 86_400) > 50

      ReviewRequest.new(time: now.to_i, ip: ip, rule: rule, email: email, message: message, user_agent: user_agent.to_s[0, 255])
    end
  end

  # The visitor's country without Cloudflare: the same file and binary search as src/Core/Geo.php.
  class GeoFile
    SOURCE = 'https://github.com/fermatacordis-create/draco-insomnis/releases/download/geo/draco-geo.bin'
    HEADER = 22

    attr_reader :path

    def initialize(path, update: true, source: SOURCE)
      @path = path
      @source = source
      @lock = Mutex.new
      @file = nil
      @tried = 0
      return unless update

      Thread.new do
        loop do
          refresh
        rescue StandardError
          nil
        ensure
          sleep 86_400
        end
      end
    end

    def country(ip)
      addr = Net.to_bytes(Net.unmap(ip.to_s.strip)) or return nil
      @lock.synchronize do
        open_file or return nil
        v4c, v6c, = @info
        is4 = addr.bytesize == 4
        count, size = is4 ? [v4c, 6] : [v6c, 18]
        width = size - 2
        base = HEADER + (is4 ? 0 : v4c * 6)
        lo = 0
        hi = count - 1
        found = -1
        while lo <= hi
          mid = (lo + hi) / 2
          @file.seek(base + (mid * size))
          if @file.read(width) <= addr
            found = mid
            lo = mid + 1
          else
            hi = mid - 1
          end
        end
        return nil if found.negative?

        @file.seek(base + (found * size) + width)
        cc = @file.read(2)
        cc.match?(/\A[A-Z]{2}\z/) ? cc : nil
      end
    end

    def built = @lock.synchronize { open_file ? @info[2] : '' }

    def stale?
      b = built
      return true if b.empty?

      Time.now.to_i - Time.utc(b[0, 4].to_i, b[4, 2].to_i, b[6, 2].to_i).to_i > 35 * 86_400
    end

    def refresh = stale? ? update : ''

    # Downloads, checks the published SHA-256, and only then replaces the old file.
    def update
      get = lambda do |url|
        uri = URI(url)
        5.times do
          res = ::Net::HTTP.get_response(uri)
          return res.body if res.is_a?(::Net::HTTPSuccess)
          return nil unless res.is_a?(::Net::HTTPRedirection)

          uri = URI(res['location'])
        end
        nil
      rescue StandardError
        nil
      end
      want = get.call("#{@source}.sha256").to_s.strip[0, 64].to_s.downcase
      return 'checksum' unless want.match?(/\A[a-f0-9]{64}\z/)

      body = get.call(@source)
      return 'download' if body.nil? || Digest::SHA256.hexdigest(body) != want
      return 'format' if self.class.head(body.b[0, HEADER], body.bytesize).nil?

      part = "#{@path}.part"
      begin
        FileUtils.mkdir_p(File.dirname(@path))
        File.binwrite(part, body)
        File.rename(part, @path)
      rescue SystemCallError
        FileUtils.rm_f(part)
        return 'folder'
      end
      close
      ''
    end

    def close
      @lock.synchronize do
        @file&.close
        @file = nil
        @tried = 0
      end
    end

    def self.head(bytes, size)
      return nil if bytes.nil? || bytes.bytesize < HEADER || bytes[0, 6] != 'DRGEO1'

      v4, v6 = bytes.byteslice(14, 8).unpack('NN')
      size == HEADER + (v4 * 6) + (v6 * 18) ? [v4, v6, bytes.byteslice(6, 8)] : nil
    end

    private

    def open_file
      return true if @file
      return false if Time.now.to_f - @tried < 60

      @tried = Time.now.to_f
      f = File.open(@path, 'rb')
      info = self.class.head(f.read(HEADER), f.size)
      if info.nil?
        f.close
        return false
      end
      @file = f
      @info = info
      true
    rescue SystemCallError
      false
    end
  end

  # Draco as a bouncer of the owner's own CrowdSec Local API, like server/src/CrowdSec.php.
  class CrowdSec
    def self.seconds(duration)
      return 0 if duration.to_s.strip.start_with?('-')

      found = duration.to_s.scan(/(\d+(?:\.\d+)?)(h|ms|m|s)/)
      return 0 if found.empty?

      found.sum { |n, u| n.to_f * { 'h' => 3600, 'm' => 60, 's' => 1, 'ms' => 0.001 }[u] }.ceil
    end

    def self.line(event, host = '')
      JSON.generate({ 'time' => Time.at(event.time).utc.strftime('%Y-%m-%dT%H:%M:%SZ'), 'ip' => event.ip, 'host' => host,
                      'endpoint' => event.endpoint, 'verdict' => event.verdict, 'reasons' => event.reasons.join(','),
                      'user_agent' => event.user_agent })
    end

    def initialize(url:, api_key:, store:, admins:, now:, timeout: 2)
      @url = url.sub(%r{/+\z}, '')
      @key = api_key
      @store = store
      @blocks = Blocks.new(store)
      @admins = admins
      @now = now
      @timeout = timeout
      @running = Mutex.new
    end

    def maybe_sync
      return if @running.locked? || @store.bump('draco:crowdsec:sync', 60) != 1

      Thread.new { sync }
    end

    def sync
      @running.synchronize { pull }
    end

    private

    def pull
      @store.set('draco:crowdsec:sync', '1', 60)
      out = { 'added' => 0, 'removed' => 0, 'error' => '' }
      startup = @store.get('draco:crowdsec:started').nil?
      uri = URI("#{@url}/v1/decisions/stream?startup=#{startup}&scopes=ip,range")
      data = nil
      begin
        res = ::Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: @timeout, read_timeout: @timeout) do |http|
          http.get(uri.request_uri, { 'X-Api-Key' => @key, 'User-Agent' => 'Draco-Insomnis' })
        end
        if res.code == '200'
          data = JSON.parse(res.body.to_s)
        else
          out['error'] = "HTTP #{res.code}"
        end
      rescue JSON::ParserError
        out['error'] = 'not JSON'
      rescue StandardError
        out['error'] = 'no answer'
      end
      now = @now.call
      if !out['error'].empty? || !data.is_a?(Hash)
        out['error'] = 'not JSON' if out['error'].empty?
        @store.set('draco:crowdsec:last', "#{now.to_i}|#{out['error']}", 86_400 * 30)
        return out
      end
      imported = begin
        JSON.parse(@store.get('draco:crowdsec:imported') || '[]')
      rescue JSON::ParserError
        []
      end
      if startup
        out['removed'] += imported.count { |v| remove_if_ours(v, now) }
        imported = []
      end
      Array(data['deleted']).each do |d|
        value = d.to_h['value'].to_s.downcase
        next unless !value.empty? && imported.include?(value) && remove_if_ours(value, now)

        out['removed'] += 1
        imported.delete(value)
      end
      admins = @admins.call
      Array(data['new']).each do |d|
        d = d.to_h
        next unless d['type'].to_s.downcase == 'ban'

        value = d['value'].to_s.strip.downcase
        ttl = self.class.seconds(d['duration'].to_s)
        allowed = value.include?('/') ? Blocks.valid_net?(value) : Net.ip?(value)
        next if ttl <= 0 || !allowed || admins.include?(value)

        reason = "CrowdSec: #{(d['scenario'] || d['origin']).to_s[0, 150]}"
        next unless @blocks.add_until(value, now.to_i + ttl, reason, automatic: true, now: now)

        out['added'] += 1
        imported << value unless imported.include?(value)
      end
      @store.set('draco:crowdsec:imported', JSON.generate(imported.last(20_000)), 0)
      @store.set('draco:crowdsec:started', '1', 86_400 * 365)
      @store.set('draco:crowdsec:last', "#{now.to_i}|ok +#{out['added']} -#{out['removed']}", 86_400 * 30)
      out
    end

    def remove_if_ours(value, now)
      e = @blocks.entry(value, now)
      return false unless e && e['reason'].to_s.start_with?('CrowdSec')

      @blocks.remove(value, now: now)
      true
    end
  end
end
