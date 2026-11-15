# frozen_string_literal: true

require 'stringio'
require 'uri'

module DracoInsomnis
  # Rack middleware: Draco answers first, the app only sees what it lets through. Forms and JSON
  # bodies up to 64 KB are read once and put back. Security headers never replace the app's own. If
  # Draco itself fails, the request goes through.
  class Rack
    MAX_BODY = 65_536

    attr_reader :gate

    def initialize(app, gate: nil, logger: nil, **options)
      @app = app
      @gate = gate || Gatekeeper.new(**options)
      return unless logger

      @gate.on_event ||= ->(e) { logger.info("[draco] #{JSON.generate(e.to_h)}") }
      @gate.on_review ||= ->(r) { logger.warn("[draco] review request #{JSON.generate(r.to_h)}") }
    end

    def call(env)
      answer = begin
        @gate.decide(self.class.read(env))
      rescue StandardError
        nil
      end
      if answer
        status, headers, body = @gate.render(answer)
        return [status, headers, [body]]
      end
      status, headers, body = @app.call(env)
      extra = @gate.security_headers(env['rack.url_scheme'] == 'https' || env['HTTPS'] == 'on')
      unless extra.empty?
        have = headers.keys.map(&:downcase)
        extra.each { |k, v| headers[k.downcase] = v unless have.include?(k.downcase) }
      end
      [status, headers, body]
    end

    # The Rack env the way Draco reads it.
    def self.read(env)
      raw_path = env['PATH_INFO'].to_s
      path = URI.decode_www_form_component(raw_path.gsub('+', '%2B')) rescue raw_path
      raw_query = env['QUERY_STRING'].to_s
      query = URI.decode_www_form_component(raw_query) rescue raw_query
      params = Waf.flatten(safe_form(raw_query))
      form = nil
      method = env['REQUEST_METHOD'].to_s.upcase
      kind = env['CONTENT_TYPE'].to_s.downcase
      length = env['CONTENT_LENGTH'].to_s
      input = env['rack.input']
      if %w[POST PUT PATCH].include?(method) && input && length.match?(/\A\d+\z/) && length.to_i <= MAX_BODY &&
         (kind.include?('json') || kind.include?('x-www-form-urlencoded'))
        input.rewind if input.respond_to?(:rewind)
        body = input.read(length.to_i).to_s
        # Handed on unchanged.
        env['rack.input'] = StringIO.new(body)
        if kind.include?('json')
          begin
            data = JSON.parse(body)
            params += Waf.flatten(data)
            form = data.select { |_, v| v.is_a?(String) } if data.is_a?(Hash)
          rescue JSON::ParserError
            params << body
          end
        else
          form = safe_form(body)
          params += Waf.flatten(form)
        end
      end
      r = Request.new(method: method, path: path, query: query, params: params,
                      user_agent: env['HTTP_USER_AGENT'].to_s, remote_addr: env['REMOTE_ADDR'].to_s,
                      cf_connecting_ip: env['HTTP_CF_CONNECTING_IP'].to_s, forwarded_for: env['HTTP_X_FORWARDED_FOR'].to_s,
                      accept: env['HTTP_ACCEPT'].to_s, ajax: env['HTTP_X_REQUESTED_WITH'].to_s.casecmp?('xmlhttprequest'), form: form)
      # Cloudflare's country header, only when the connection really comes from Cloudflare.
      r.country = env['HTTP_CF_IPCOUNTRY'].to_s if Net.contains?(Net::CLOUDFLARE, Net.unmap(r.remote_addr))
      r
    end

    def self.safe_form(text)
      URI.decode_www_form(text.to_s).to_h
    rescue ArgumentError
      {}
    end
  end
end
