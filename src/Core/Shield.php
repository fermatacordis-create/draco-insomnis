<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * Judges public sign-ups before an account exists. The CMS adapter adds the hidden inputs to its forms,
 * calls judge() from its own registration hook and, for a bot, calls slowDown() and answers as if
 * the sign-up worked (or with a plain refusal where the form cannot be fooled).
 *
 * Only defends the site: nothing is ever sent back to the attacker's machine.
 */
final class Shield
{
    public const AUTO_BLOCK_AFTER = 3;
    public const AUTO_BLOCK_DAYS = 7;
    /** Slow answers allowed per minute across the whole site, so a flood cannot use up PHP workers. */
    private const SLOW_PER_MINUTE = 10;
    private const SLOW_MAX_MS = 3000;
    private const TRAP_WORDS = ['website', 'homepage', 'company_site', 'web_address', 'url_home'];

    public function __construct(private Host $host)
    {
    }

    /** Name of the hidden page-stamp input, different on every site. */
    public function stampField(): string
    {
        return 'dr_' . substr(hash('sha256', 'stamp|' . $this->host->secret()), 0, 8);
    }

    /** Name of the trap input, different on every site. */
    public function trapField(): string
    {
        $h = hash('sha256', 'trap|' . $this->host->secret());

        return self::TRAP_WORDS[hexdec($h[0]) % count(self::TRAP_WORDS)] . '_' . substr($h, 1, 4);
    }

    public function stamp(int $now): string
    {
        return FormStamp::make($this->host->secret(), $now);
    }

    /** Both hidden inputs, ready for any form. */
    public function fieldsHtml(int $now): string
    {
        return '<input type="hidden" name="' . self::attr($this->stampField()) . '" value="' . self::attr($this->stamp($now)) . '">' . $this->trapHtml();
    }

    /** Out of sight and out of the tab order; people and password managers leave it empty. */
    public function trapHtml(): string
    {
        return '<div aria-hidden="true" style="position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden">'
            . '<label>Website <input type="text" name="' . self::attr($this->trapField()) . '" value="" tabindex="-1" autocomplete="off"></label></div>';
    }

    /**
     * @param array{username: string, email: string, role: string} $fields
     * @param list<string>|null $roles Roles the form offers, when it offers any.
     * @return array{score: int, verdict: string, reasons: list<string>}
     */
    public function judge(Request $r, string $endpoint, array $fields, ?array $roles, int $now): array
    {
        $ip = $r->via($this->host);
        $remote = $r->remote();
        $events = $this->host->events();
        $stamp = FormStamp::check($this->host->secret(), $r->field($this->stampField()), $now);
        $ua = substr($r->userAgent, 0, 255);
        $result = BotScore::evaluate([
            'blocked' => $events->isBlocked($fields['email'], $ip),
            'requested_role' => $fields['role'],
            'allowed_roles' => $roles,
            'honeypot' => $r->field($this->trapField()),
            'stamp' => $stamp['state'],
            'elapsed' => $stamp['elapsed'],
            'username' => $fields['username'],
            'hosting_network' => NetList::contains($this->nets(), $ip),
            'recent_bot_attempts' => $events->botAttemptsSince($ip, 86400),
            'user_agent' => $ua,
        ]);
        $result = (array) $this->host->filter('verdict', $result, $endpoint, $fields, $ip);
        if ($result['verdict'] !== 'clean') {
            $events->log($ip, $remote, $endpoint, $result, $ua, [
                'username' => substr($fields['username'], 0, 60),
                'email' => substr($fields['email'], 0, 120),
                'role' => substr($fields['role'], 0, 60),
                'referer' => substr($r->referer, 0, 200),
            ]);
        }
        if ($result['verdict'] === 'bot') {
            $this->maybeAutoBlock($ip, $remote);
        }

        return $result;
    }

    /**
     * Three bot attempts in a day block the address for a week. Only when the address is the
     * connection's own, or comes from a proxy header the administrator chose to trust: otherwise a
     * forged header could get an innocent visitor blocked.
     */
    private function maybeAutoBlock(string $ip, string $remote): void
    {
        $events = $this->host->events();
        $trusted = $ip === $remote || $this->host->setting('proxy_header') !== '';
        if (!$trusted || $events->isBlocked('', $ip)) {
            return;
        }
        if ($events->botAttemptsSince($ip, 86400) >= self::AUTO_BLOCK_AFTER) {
            $events->block('ip', $ip, self::AUTO_BLOCK_DAYS, $this->host->text('auto_block', self::AUTO_BLOCK_AFTER), true);
        }
    }

    /** A few seconds, never more, and only while the site has workers to spare. */
    public function slowDown(): void
    {
        $used = $this->host->bump('draco_slow_' . gmdate('YmdHi'), 120);
        if ($used <= self::SLOW_PER_MINUTE) {
            usleep(random_int(intdiv(self::SLOW_MAX_MS, 2), self::SLOW_MAX_MS) * 1000);
        }
    }

    /** Rented-server ranges: the ones seen in the wild plus the site's own list. @return list<string> */
    public function nets(): array
    {
        $own = NetList::parse($this->host->setting('hosting_nets'));

        return (array) $this->host->filter('hosting_nets', array_merge(NetList::SEEN_HOSTING, $own));
    }

    private static function attr(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
    }
}
