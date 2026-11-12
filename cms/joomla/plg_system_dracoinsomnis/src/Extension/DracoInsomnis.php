<?php

/**
 * @package     Draco Insomnis for Joomla
 * @copyright   (C) 2026 Notorius Vision
 * @license     GNU General Public License version 2 or later
 */

namespace Notorius\Plugin\System\DracoInsomnis\Extension;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Core\Pace;
use DracoInsomnis\Core\Shield;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Router\Route;
use Joomla\CMS\Session\Session;
use Joomla\Event\Event;
use Joomla\Event\SubscriberInterface;
use Notorius\Plugin\System\DracoInsomnis\JoomlaHost;
use Notorius\Plugin\System\DracoInsomnis\Store;

\defined('_JEXEC') or die;

/**
 * Draco Insomnis for Joomla. Ab insomni custodita dracone.
 *
 * - onAfterInitialise: firewall and anti-copy pace limit, as early as the site allows.
 * - onAfterRender: the page stamp and the trap go into the sign-up form.
 * - onAfterRoute: a sign-up is judged before com_users creates the account.
 * - onAjaxDracoinsomnis: the evidence CSV and unblocking, for administrators.
 *
 * The deciding code is the same as in the WordPress plugin (lib/Core).
 * Emergency exit: define('DRACO_WAF_OFF', true); in defines.php at the site root.
 */
final class DracoInsomnis extends CMSPlugin implements SubscriberInterface
{
    protected $autoloadLanguage = true;

    public static function getSubscribedEvents(): array
    {
        return [
            'onAfterInitialise' => 'onAfterInitialise',
            'onAfterRoute' => 'onAfterRoute',
            'onAfterRender' => 'onAfterRender',
            'onAjaxDracoinsomnis' => 'onAjax',
        ];
    }

    private function host(): JoomlaHost
    {
        return new JoomlaHost($this->params);
    }

    public function onAfterInitialise(Event $event): void
    {
        $app = $this->getApplication();
        $user = $app->getIdentity();
        $host = $this->host();
        if ($app->isClient('administrator')) {
            if ($user && $user->authorise('core.admin')) {
                $host->rememberAdminIp(JoomlaHost::request()->via($host));
            }
            return;
        }
        if (!$app->isClient('site')) {
            return;
        }
        $request = JoomlaHost::request();
        $staff = $user && !$user->guest && $user->authorise('core.login.admin');

        $waf = $host->mode('waf_mode');
        if ($waf !== 'off' && !$staff && !(\defined('DRACO_WAF_OFF') && DRACO_WAF_OFF)) {
            $firewall = new Firewall($host, $waf === 'block');
            if (!$firewall->exempt($request)) {
                // Addresses on the block list may read the site, but not post anything.
                if ($firewall->refusedAsBlocked($request, [])) {
                    $this->deny('blocked');
                }
                $rule = $firewall->inspect($request);
                if ($rule !== null && $firewall->blocking()) {
                    $this->deny($rule);
                }
            }
        }

        $pace = $host->mode('pace_mode');
        if ($pace !== 'off' && (!$user || $user->guest)) {
            $engine = new Pace($host);
            $count = $engine->count($request, time());
            if ($count['over'] !== '' && !$engine->exempt($request)) {
                $block = $pace === 'block';
                // One line per address and minute is enough evidence; the rest only counts.
                if ($count['first']) {
                    $engine->record($request, 'rate_' . $count['over'], $block, $request->path);
                }
                if ($block) {
                    $this->tooMany($count['retry']);
                }
            }
        }

        Store::maybeCleanup();
    }

    /** A sign-up is judged here, before com_users creates the account. */
    public function onAfterRoute(Event $event): void
    {
        $app = $this->getApplication();
        $host = $this->host();
        if (!$app->isClient('site') || !$host->shieldOn()) {
            return;
        }
        $input = $app->getInput();
        if ($input->getMethod() !== 'POST' || $input->getCmd('option') !== 'com_users' || $input->getCmd('task') !== 'registration.register') {
            return;
        }
        $user = $app->getIdentity();
        if ($user && !$user->guest) {
            return;
        }
        $form = $input->post->get('jform', [], 'array');
        $shield = new Shield($host);
        $result = $shield->judge(JoomlaHost::request(), 'joomla_register', [
            'username' => JoomlaHost::clean((string) ($form['username'] ?? '')),
            'email' => JoomlaHost::clean((string) ($form['email1'] ?? '')),
            'role' => '',
        ], null, time());
        if ($result['verdict'] !== 'bot') {
            return;
        }
        $shield->slowDown();
        $app->enqueueMessage(Text::_('PLG_SYSTEM_DRACOINSOMNIS_REJECTED'), 'error');
        $app->redirect(Route::_('index.php?option=com_users&view=registration', false));
    }

    /** The page stamp and the trap go into the sign-up form. */
    public function onAfterRender(Event $event): void
    {
        $app = $this->getApplication();
        if (!$app->isClient('site') || !$this->host()->shieldOn()) {
            return;
        }
        $user = $app->getIdentity();
        if ($user && !$user->guest) {
            return;
        }
        $body = (string) $app->getBody();
        $start = strpos($body, 'id="member-registration"');
        if ($start === false) {
            return;
        }
        $end = strpos($body, '</form>', $start);
        if ($end === false) {
            return;
        }
        $fields = (new Shield($this->host()))->fieldsHtml(time());
        $app->setBody(substr($body, 0, $end) . $fields . substr($body, $end));
    }

    /**
     * index.php?option=com_ajax&group=system&plugin=dracoinsomnis&format=raw&action=csv|unblock&<token>=1
     * Administrators only, with the session token.
     */
    public function onAjax(Event $event): void
    {
        $app = $this->getApplication();
        $user = $app->getIdentity();
        if (!$app->isClient('administrator') || !$user || !$user->authorise('core.admin') || !Session::checkToken('get')) {
            throw new \RuntimeException(Text::_('JERROR_ALERTNOAUTHOR'), 403);
        }
        $input = $app->getInput();
        $action = $input->getCmd('action');
        if ($action === 'unblock') {
            Store::unblock($input->getInt('id'));
            $app->enqueueMessage(Text::_('PLG_SYSTEM_DRACOINSOMNIS_UNBLOCKED'));
            $app->redirect((string) $input->server->getString('HTTP_REFERER', 'index.php?option=com_plugins'));
        }
        if ($action === 'csv') {
            $ip = $input->getString('ip');
            if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
                throw new \RuntimeException('Bad address', 404);
            }
            header('Content-Type: text/csv; charset=UTF-8');
            header('Content-Disposition: attachment; filename="draco-evidence-' . str_replace(':', '-', $ip) . '.csv"');
            header('Cache-Control: no-store');
            $out = fopen('php://output', 'w');
            fputcsv($out, ['created_at_utc', 'ip', 'remote_addr', 'endpoint', 'verdict', 'score', 'reasons', 'user_agent', 'fields'], ',', '"', '\\');
            foreach (Store::byIp($ip) as $row) {
                fputcsv($out, [$row['created_at'], $row['ip'], $row['remote_addr'], $row['endpoint'], $row['verdict'], $row['score'], $row['reasons'], $row['user_agent'], $row['fields']], ',', '"', '\\');
            }
            fclose($out);
            $app->close();
        }
    }

    /** No details for the attacker: what matched stays in the log. */
    private function deny(string $why): void
    {
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/html; charset=UTF-8');
            header('Cache-Control: no-store');
            header('X-Robots-Tag: noindex, nofollow');
        }
        echo Firewall::page(Text::_('PLG_SYSTEM_DRACOINSOMNIS_BLOCKED_TITLE'), Text::_('PLG_SYSTEM_DRACOINSOMNIS_BLOCKED_TEXT'), $why);
        $this->getApplication()->close();
    }

    private function tooMany(int $seconds): void
    {
        if (!headers_sent()) {
            http_response_code(429);
            header('Retry-After: ' . max(1, $seconds));
            header('Content-Type: text/plain; charset=UTF-8');
            header('Cache-Control: no-store');
            header('X-Robots-Tag: noindex');
        }
        echo 'Too many requests. Please wait a minute.';
        $this->getApplication()->close();
    }
}
