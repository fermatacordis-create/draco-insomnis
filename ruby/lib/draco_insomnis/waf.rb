# frozen_string_literal: true

module DracoInsomnis
  # The attack signatures of src/Core/WafRules.php and every other edition, kept in step by the shared
  # cases in tests/vectors/waf.json. Ruby's ^ and $ are line anchors: \A and \Z are used instead, so
  # they mean what PHP's ^ and $ mean. \w, \s and \b are ASCII here, like PHP's.
  module Waf
    SCANNERS = /\b(sqlmap|nikto|wpscan|nmap|masscan|zgrab|nuclei|acunetix|dirbuster|gobuster|ffuf|feroxbuster|wfuzz|whatweb|openvas|netsparker|jaeles|hydra)\b/i

    PROBES = %r{(\A|/)(\.env(\.[a-z0-9]+)?\Z|\.git(/|\Z)|\.svn/|\.hg/|\.aws/|\.ssh/|\.ds_store\Z|wp-config\.php[^/]+\Z|wp-config\.(bak|old|txt|orig|save|swp)\Z|phpinfo\.php\Z|info\.php\Z|adminer[\w.-]*\.php\Z|eval-stdin\.php\Z|vendor/phpunit/|[\w.-]+\.sql(\.gz|\.zip)?\Z|[\w.-]+\.log(\.\d+|\.gz)?\Z|error_log\Z|(storage|var)/logs?/|\.ht(access|passwd)\Z|core/install\.php\Z|wp-admin/(install|setup-config)\.php\Z|(phpmyadmin|phppgadmin)[\w.-]*(/|\Z)|pma(/|\Z)|[\w.-]+\.(bak|old|orig|save|swp)\Z|(backup|backups|dump|database)[\w.-]*\.(zip|tar|tgz|gz|bz2|7z|rar)\Z|server-status\Z|cgi-bin/|(wso|c99|r57|alfa[\w-]*|shell|webshell|b374k)\.php\Z)}i

    SP = '(\s|/\*.*?\*/|\+)'

    SQLI = [
      # "union select" followed by a column list, not by a word: "European Union Select Committee" passes.
      Regexp.new("\\bunion\\b#{SP}+(all#{SP}+|distinct#{SP}+)?select#{SP}*(\\d|null\\b|@@|\\*|0x|['\"(]|concat|char\\s*\\(|group_concat|[a-z_.`]+\\s*,)", Regexp::IGNORECASE | Regexp::MULTILINE),
      # A single column right after a quote, a whole number value or a bracket.
      Regexp.new("(['\")]|(\\A|[=&])-?\\d+)#{SP}*\\bunion\\b#{SP}+(all#{SP}+)?select#{SP}+[a-z_.`]+#{SP}+from\\b", Regexp::IGNORECASE | Regexp::MULTILINE),
      /\bselect\b.{1,120}\bfrom\b.{1,120}\b(information_schema|mysql\.user|pg_catalog)\b/im,
      /\b(sleep|benchmark|pg_sleep)\s*\(\s*\d/i,
      /\bwaitfor\s+delay\s+'/i,
      /'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+/i,
      %r{\b(or|and)\s+\d+\s*=\s*\d+\s*(--|#|/\*)}i,
      /;\s*(drop|truncate|alter)\s+table\b/i
    ].freeze

    TRAVERSAL = [
      %r{(\.\.[/\\]){2,}},
      %r{\b(etc/passwd|etc/shadow|proc/self/environ|boot\.ini|win\.ini)\b}i,
      %r{\b(php|expect|phar|zip|data)://}i
    ].freeze

    CODE = [
      /\$\{\s*jndi\s*:/i,
      /\b(base64_decode|eval|assert|system|shell_exec|passthru|proc_open|popen)\s*\(/i,
      %r{\b(wget|curl)\s+(-[a-z]+\s+)*https?://}i,
      /<\?php/i
    ].freeze

    XSS_URL = [
      /<\s*script\b/i,
      /\bjavascript\s*:/i,
      /<\s*(svg|img|iframe|body|details)\b[^>]*\bon[a-z]+\s*=/i,
      /["'\s]on(error|load|mouseover|focus|toggle)\s*=/i
    ].freeze

    PCT = /%([0-9a-f]{2})/i

    module_function

    # Byte-wise %XX decoding like PHP's rawurldecode (never fails on malformed input).
    def raw_url_decode(value)
      value.b.gsub(PCT) { Regexp.last_match(1).to_i(16).chr }.force_encoding(Encoding::BINARY)
    end

    def decoded_again(value)
      return '' unless value.match?(PCT)

      again = raw_url_decode(value)
      again == value.b ? '' : again
    end

    # ASCII-only matching on any bytes, like PHP's byte-wise PCRE.
    def ascii(value)
      value.to_s.b
    end

    # The rule a request breaks ("scanner", "probe", "sqli", "traversal", "code", "xss"), or nil.
    def inspect_request(path: '', query: '', params: [], user_agent: '')
      path = ascii(path)
      query = ascii(query)
      params = params.map { |p| ascii(p) }
      return 'scanner' if SCANNERS.match?(ascii(user_agent))
      return 'probe' if PROBES.match?(path)

      # Encoded twice (%2527 -> %27 -> '): look at the second decoding too. Nothing is changed.
      path2 = decoded_again(path)
      query2 = decoded_again(query)
      everything = [path, query, path2, query2, *params, *params.map { |v| decoded_again(v) }]
      [['sqli', SQLI], ['traversal', TRAVERSAL], ['code', CODE]].each do |rule, patterns|
        everything.each do |v|
          return rule if !v.empty? && patterns.any? { |p| p.match?(v) }
        end
      end
      [path, query, path2, query2].each do |v|
        return 'xss' if !v.empty? && XSS_URL.any? { |p| p.match?(v) }
      end
      nil
    end

    # Nested request values (params hashes, decoded JSON) as strings, keys too, at most +limit+.
    def flatten(value, limit = 200)
      out = []
      walk = lambda do |v, depth|
        return if out.size >= limit

        case v
        when Hash
          return if depth >= 5

          v.each do |k, item|
            out << k.to_s unless k.to_s.empty?
            walk.call(item, depth + 1)
          end
        when Array
          return if depth >= 5

          v.each { |item| walk.call(item, depth + 1) }
        when true then out << '1'
        when false then out << ''
        when String, Numeric then out << v.to_s
        end
      end
      walk.call(value, 0)
      out.first(limit)
    end
  end
end
