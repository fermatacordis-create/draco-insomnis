<?php
/**
 * @author    Notorius Vision
 * @license   GPL-2.0-or-later
 */

declare(strict_types=1);

namespace DracoInsomnis\Presta;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Core\Gatekeeper;
use DracoInsomnis\Core\SecurityHeaders;
use DracoInsomnis\Core\Shield;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * The shop side: firewall and pace limit on every request, the shield on customer sign-ups.
 *
 * Emergency exit for the owner: define('DRACO_WAF_OFF', true); in config/defines_custom.inc.php
 * switches the firewall off without the back office.
 */
final class Front
{
    public static function request(\DracoInsomnis $module): void
    {
        $host = PsHost::get();
        $request = PsHost::request();

        $waf = (defined('DRACO_WAF_OFF') && DRACO_WAF_OFF) ? 'off' : Settings::mode(Settings::WAF_MODE);
        // POST is always sensitive; these are the login, sign-up and password pages in their usual addresses.
        $answer = (new Gatekeeper($host))->decide($request, $waf, Settings::mode(Settings::PACE_MODE),
            ['controller=authentication', 'controller=registration', 'controller=password', '/login', '/registration', '/password-recovery', '/registro', '/iniciar-sesion'],
            !self::customerLoggedIn());
        if ($answer !== null) {
            $answer['status'] === 429 ? self::tooMany($answer['retry']) : self::deny($module, $answer['why']);
        }
        SecurityHeaders::send(SecurityHeaders::wanted($host, \Tools::usingSecureMode()));

        Store::maybeCleanup();
    }

    public static function formFields(\Context $context): string
    {
        if (Settings::get(Settings::SHIELD) !== '1' || self::customerLoggedIn()) {
            return '';
        }

        return (new Shield(PsHost::get()))->fieldsHtml(time());
    }

    /** False stops the sign-up before the account exists. */
    public static function judgeSignUp(\DracoInsomnis $module): bool
    {
        if (Settings::get(Settings::SHIELD) !== '1' || self::customerLoggedIn()) {
            return true;
        }
        $request = PsHost::request();
        $shield = new Shield(PsHost::get());
        // No usernames in a shop: the name is where sign-up bots put their random strings.
        $name = (string) preg_replace('/\s+/', '', $request->field('firstname') . $request->field('lastname'));
        $endpoint = \Tools::getValue('controller') === 'order' ? 'ps_checkout' : 'ps_register';
        $result = $shield->judge($request, $endpoint, ['username' => $name, 'email' => $request->field('email'), 'role' => ''], null, time());
        if ($result['verdict'] !== 'bot') {
            return true;
        }
        $shield->slowDown();
        $controller = \Context::getContext()->controller;
        if ($controller !== null) {
            $controller->errors[] = $module->t('The registration could not be completed.');
        }

        return false;
    }

    private static function customerLoggedIn(): bool
    {
        $cookie = \Context::getContext()->cookie;

        return $cookie !== null && (int) $cookie->id_customer > 0 && (bool) $cookie->logged;
    }

    /** No details for the attacker: what matched stays in the log. */
    private static function deny(\DracoInsomnis $module, string $why): void
    {
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/html; charset=UTF-8');
            header('Cache-Control: no-store');
            header('X-Robots-Tag: noindex, nofollow');
        }
        echo Firewall::page(
            $module->t('Request blocked'),
            $module->t('This request was stopped for security reasons. If you think this is a mistake, contact the owner of the shop.'),
            $why
        );
        exit;
    }

    private static function tooMany(int $seconds): void
    {
        if (!headers_sent()) {
            http_response_code(429);
            header('Retry-After: ' . max(1, $seconds));
            header('Content-Type: text/plain; charset=UTF-8');
            header('Cache-Control: no-store');
            header('X-Robots-Tag: noindex');
        }
        echo 'Too many requests. Please wait a minute.';
        exit;
    }
}
