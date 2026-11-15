# frozen_string_literal: true

module DracoInsomnis
  # One visitor request in plain values.
  Request = Struct.new(:method, :path, :query, :params, :user_agent, :remote_addr, :cf_connecting_ip,
                       :forwarded_for, :country, :accept, :ajax, :form, keyword_init: true) do
    def initialize(**kw)
      super(method: 'GET', path: '/', query: '', params: [], user_agent: '', remote_addr: '', cf_connecting_ip: '',
            forwarded_for: '', country: '', accept: '', ajax: false, form: nil, **kw)
    end
  end

  # What stops a request: 403 (rule), 429 (pace) or 200 (the review thanks page).
  Answer = Struct.new(:status, :why, :retry, :form, keyword_init: true)

  # The decision for one request, in the same order as every edition:
  # block list -> country -> signatures -> pace.
  class Gatekeeper
    SENSITIVE = %w[/wp-login.php /login /register /signup /user/login /user/register /admin /auth/login
                   /api/auth/local /api/auth/local/register /admin/login /users/sign_in /users/sign_up
                   /users/password /session /sessions].freeze

    TEXTS = {
      'title' => 'Request blocked',
      'text' => "This request was blocked by the site's security. If you think this is a mistake, contact the site owner.",
      'too_many' => 'Too many pages in a short time. Please wait a moment and try again.',
      'text_with_review' => "This request was blocked by the site's security. If you think this is a mistake, tell the site owner what you were doing:",
      'review_email' => 'Your e-mail', 'review_message' => 'What were you doing?', 'review_button' => 'Ask for a review',
      'review_sent_title' => 'Request sent',
      'review_sent_text' => 'Thank you. The owner of the site will look at it and, if it was a mistake, let you through.'
    }.freeze

    CRAWLERS = {
      'googlebot' => %w[googlebot.com google.com googleusercontent.com], 'google-inspectiontool' => %w[googlebot.com google.com googleusercontent.com],
      'googleother' => %w[googlebot.com google.com googleusercontent.com], 'adsbot-google' => %w[googlebot.com google.com googleusercontent.com],
      'mediapartners-google' => %w[googlebot.com google.com googleusercontent.com], 'bingbot' => %w[search.msn.com],
      'msnbot' => %w[search.msn.com], 'adidxbot' => %w[search.msn.com], 'applebot' => %w[applebot.apple.com],
      'yandex' => %w[yandex.ru yandex.net yandex.com]
    }.freeze

    attr_reader :store, :blocks, :crowdsec, :options
    attr_accessor :on_event, :on_review, :resolver, :now

    # Options: waf ("off", "log" default, "block"), pace ("off" default, "log", "block"), rate_ip,
    # rate_net, proxy ("", "cf", "xff"), trusted_proxies, admin_ips, sensitive, except, headers, hsts,
    # geo ({mode:, countries:, action:, scope:, lookup: GeoFile}), review ({secret:}),
    # crowdsec ({url:, api_key:}), texts, store, on_event, on_review.
    def initialize(**opts)
      @options = { waf: 'log', pace: 'off' }.merge(opts)
      @now = opts[:now] || -> { Time.now.to_f }
      @store = opts[:store] || MemoryStore.new(@now)
      @blocks = Blocks.new(@store)
      @resolver = opts.key?(:resolver) ? opts[:resolver] : Resolv
      @texts = TEXTS.merge((opts[:texts] || {}).transform_keys(&:to_s))
      @trusted = Net.parse(Array(opts[:trusted_proxies]))
      @admins = Array(opts[:admin_ips]).map(&:strip).reject(&:empty?)
      @on_event = opts[:on_event]
      @on_review = opts[:on_review]
      cs = opts[:crowdsec] || {}
      @crowdsec = if cs[:url] && cs[:api_key]
                    CrowdSec.new(url: cs[:url], api_key: cs[:api_key], store: @store, admins: -> { @admins },
                                 now: -> { @now.call }, timeout: cs[:timeout] || 2)
                  end
    end

    def ip(r)
      addr = remote(r)
      case @options[:proxy].to_s
      when 'cf'
        cf = r.cf_connecting_ip.to_s.strip
        return cf if !cf.empty? && (Net.contains?(Net::CLOUDFLARE, addr) || Net.contains?(@trusted, addr)) && Net.ip?(cf)
      when 'xff'
        proxies = @trusted.empty? ? Net::LOCAL_PROXIES : @trusted
        return addr if r.forwarded_for.to_s.strip.empty? || !Net.contains?(proxies, addr)

        r.forwarded_for.split(',').map(&:strip).reverse_each do |hop|
          return addr unless Net.ip?(hop)
          return hop unless Net.contains?(proxies, hop)

          addr = hop
        end
      end
      addr
    end

    def decide(r)
      answer = rules(r)
      if answer&.status == 403 && reviewing?
        answer.form = Review.form(@options[:review][:secret], ip(r), answer.why, @now.call, @texts)
      end
      answer
    end

    def security_headers(https)
      out = {}
      if @options[:headers]
        out['X-Content-Type-Options'] = 'nosniff'
        out['X-Frame-Options'] = 'SAMEORIGIN'
        out['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        out['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), interest-cohort=()'
      end
      out['Strict-Transport-Security'] = 'max-age=15552000' if https && @options[:hsts]
      out
    end

    # [status, headers, body] of an answer.
    def render(answer)
      t = @texts
      if answer.status == 429
        return [429, { 'retry-after' => answer.retry.to_s, 'content-type' => 'text/plain; charset=UTF-8',
                       'cache-control' => 'no-store', 'x-robots-tag' => 'noindex' }, t['too_many']]
      end
      h = { 'content-type' => 'text/html; charset=UTF-8', 'cache-control' => 'no-store', 'x-robots-tag' => 'noindex, nofollow' }
      return [200, h, self.class.page(t['review_sent_title'], t['review_sent_text'])] if answer.status == 200
      return [403, h, self.class.page(t['title'], t['text_with_review'], answer.form)] if answer.form

      [403, h, self.class.page(t['title'], t['text'])]
    end

    # The 403 page: it never says which rule matched; the reference ties it to the evidence.
    def self.page(title, text, extra = '')
      h = ->(s) { CGI.escapeHTML(s.to_s) }
      '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow">' \
        '<meta name="viewport" content="width=device-width,initial-scale=1"><title>403</title>' \
        '<style>body{font:16px/1.5 system-ui,sans-serif;background:#f4f5f7;color:#1d2327;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:20px;box-sizing:border-box}main{background:#fff;border-radius:12px;padding:32px;max-width:440px;width:100%;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}form{text-align:left;margin-top:20px}label{display:block;font-size:14px;margin:10px 0 4px}input,textarea{width:100%;box-sizing:border-box;padding:8px;border:1px solid #c3c4c7;border-radius:6px;font:inherit}button{margin-top:12px;padding:9px 16px;border:0;border-radius:6px;background:#2271b1;color:#fff;font:inherit;cursor:pointer}.hp{position:absolute;left:-9999px}</style></head><body><main>' \
        "<h1 style=\"font-size:20px\">#{h.call(title)}</h1><p>#{h.call(text)}</p>#{extra}" \
        "<p style=\"color:#64748b;font-size:13px\">Ref. #{SecureRandom.hex(5)}</p></main></body></html>"
    end

    def verified_crawler?(ip, user_agent)
      ua = user_agent.to_s.downcase
      token = CRAWLERS.keys.find { |t| ua.include?(t) }
      return false if token.nil? || @resolver.nil?

      key = "draco:crawler:#{ip}:#{token}"
      cached = @store.get(key)
      return cached == 'y' if %w[y n].include?(cached)

      ok = resolves_back?(ip, token)
      @store.set(key, ok ? 'y' : 'n', 86_400)
      ok
    end

    private

    def reviewing? = @options.dig(:review, :secret).to_s.size >= 16

    def remote(r)
      ip = Net.unmap(r.remote_addr.to_s.strip)
      Net.ip?(ip) ? ip : '0.0.0.0'
    end

    def rules(r)
      @crowdsec&.maybe_sync
      o = @options
      ip = ip(r)
      return nil if Array(o[:except]).any? { |p| (prefix = "/#{p.sub(%r{\A/+}, '')}") != '/' && r.path.start_with?(prefix) }

      if reviewing? && Review.accepted_form?(r)
        req = Review.accept(@store, o[:review][:secret], ip, r.user_agent, r.form, @now.call)
        if req
          log(r, ip, 'review', 'pending', ["review_#{req.rule.empty? ? 'blocked' : req.rule}"], req.message, req.email)
          begin
            @on_review&.call(req)
          rescue StandardError
            nil
          end
        end
        # The same answer either way, so a script learns nothing.
        return Answer.new(status: 200, why: 'review', retry: 0)
      end
      return nil if @admins.include?(ip)

      if o[:waf].to_s != 'off'
        return Answer.new(status: 403, why: 'blocked', retry: 0) if sensitive?(r) && @blocks.blocked?(ip, @now.call)

        country = refused_country(r, ip)
        unless country.empty?
          blocking = o.dig(:geo, :action).to_s == 'block'
          log(r, ip, 'waf:geo', blocking ? 'bot' : 'doubtful', ['waf_geo'], "#{country} #{r.path}")
          return Answer.new(status: 403, why: 'geo', retry: 0) if blocking
        end
        rule = Waf.inspect_request(path: r.path, query: r.query, params: r.params, user_agent: r.user_agent)
        if rule
          record(r, ip, rule, o[:waf].to_s == 'block')
          return Answer.new(status: 403, why: rule, retry: 0) if o[:waf].to_s == 'block'
        end
      end
      pace(r, ip)
    end

    def pace(r, ip)
      mode = @options[:pace].to_s
      return nil if mode == 'off' || mode.empty? || !page?(r)

      now = @now.call
      minute = (now / 60).floor
      ip_hits = @store.bump("draco:rl:i:#{ip}:#{minute}", 120)
      net_hits = @store.bump("draco:rl:n:#{Net.network(ip)}:#{minute}", 120)
      ip_limit = limit(@options[:rate_ip], 120)
      net_limit = limit(@options[:rate_net], 600)
      over = if ip_hits > ip_limit then 'ip' elsif net_hits > net_limit then 'net' end
      return nil if over.nil? || verified_crawler?(ip, r.user_agent)

      block = mode == 'block'
      if ip_hits == ip_limit + 1 || net_hits == net_limit + 1
        log(r, ip, "anticopy:#{over}", 'doubtful', ["anticopy_#{over}_#{block ? 'block' : 'log'}"], r.path)
      end
      block ? Answer.new(status: 429, why: 'pace', retry: [1, 60 - (now.to_i % 60)].max) : nil
    end

    def limit(v, fallback) = v.to_i >= 10 ? v.to_i : fallback

    def page?(r)
      accept = r.accept.to_s.downcase
      %w[GET HEAD].include?(r.method) && (accept.empty? || accept.include?('text/html')) && !r.ajax
    end

    def sensitive?(r)
      return true if r.method == 'POST'

      endings = Array(@options[:sensitive]).empty? ? SENSITIVE : Array(@options[:sensitive])
      endings.any? { |e| !e.empty? && r.path.end_with?(e) }
    end

    def refused_country(r, ip)
      geo = @options[:geo] || {}
      mode = geo[:mode].to_s
      list = Array(geo[:countries]).map { |c| c.to_s.strip.upcase }.select { |c| c.match?(/\A[A-Z]{2}\z/) }
      return '' if mode.empty? || mode == 'off' || list.empty?
      return '' if geo[:scope].to_s != 'site' && !sensitive?(r)

      country = r.country.to_s.upcase
      country = geo[:lookup].country(ip).to_s.upcase if !country.match?(/\A[A-Z]{2}\z/) && geo[:lookup]
      return '' if !country.match?(/\A[A-Z]{2}\z/) || %w[XX T1].include?(country)

      listed = list.include?(country)
      return '' if (mode == 'block' && !listed) || (mode == 'allow' && listed)
      return '' if verified_crawler?(ip, r.user_agent)

      country
    rescue StandardError
      ''
    end

    def record(r, ip, rule, blocking)
      log(r, ip, "waf:#{rule}", blocking ? 'bot' : 'doubtful', ["waf_#{rule}"], r.path + (r.query.empty? ? '' : "?#{r.query}"))
      return unless blocking

      hits = @store.bump("draco:waf:#{ip}", 600)
      # An address read from a header nobody vouches for is never blocked: it could be anybody's.
      trusted = ip == remote(r) || !@options[:proxy].to_s.empty?
      return unless hits >= 5 && trusted && !@blocks.blocked?(ip, @now.call)

      @blocks.add(ip, 7, "Firewall: #{hits} attacks in 10 minutes", automatic: true, now: @now.call)
    end

    def resolves_back?(ip, token)
      want = Net.from_bytes(Net.to_bytes(ip))
      Array(@resolver.getnames(ip)).first(3).any? do |name|
        h = name.to_s.downcase.strip.chomp('.')
        next false unless CRAWLERS[token].any? { |d| h == d || h.end_with?(".#{d}") }

        Array(@resolver.getaddresses(h)).any? { |a| (b = Net.to_bytes(a.to_s)) && Net.from_bytes(b) == want }
      end
    rescue StandardError
      false
    end

    def log(r, ip, endpoint, verdict, reasons, detail, email = nil)
      return unless @on_event

      @on_event.call(Event.new(time: @now.call.to_i, ip: ip, remote: remote(r), endpoint: endpoint, verdict: verdict,
                               reasons: reasons, user_agent: r.user_agent.to_s[0, 255],
                               detail: detail.to_s[0, endpoint == 'review' ? 500 : 200], email: email))
    rescue StandardError
      nil
    end
  end

  module Review
    module_function

    def accepted_form?(r) = r.method == 'POST' && r.form.is_a?(Hash) && r.form[FIELD].to_s == '1'
  end
end
