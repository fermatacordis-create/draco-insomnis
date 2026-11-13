<?php

/**
 * @package     Draco Insomnis for Joomla
 * @copyright   (C) 2026 Notorius Vision
 * @license     GNU General Public License version 2 or later
 */

namespace Notorius\Plugin\System\DracoInsomnis\Extension;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Core\Gatekeeper;
use DracoInsomnis\Core\Review;
use DracoInsomnis\Core\TestProbe;
use DracoInsomnis\Core\Geo;
use DracoInsomnis\Core\GeoUpdate;
use DracoInsomnis\Core\SecurityHeaders;
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
            'onExtensionAfterSave' => 'onExtensionAfterSave',
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
        $guest = !$user || $user->guest;
        $waf = ($staff || (\defined('DRACO_WAF_OFF') && DRACO_WAF_OFF)) ? 'off' : $host->mode('waf_mode');
        $probe = TestProbe::answer($host, (string) ($_SERVER['HTTP_X_DRACO_TEST'] ?? ''), $waf, time());
        if ($probe !== null) {
            if (!headers_sent()) {
                http_response_code($probe['status']);
                header(TestProbe::RESULT . ': ' . $probe['result']);
                header('Cache-Control: no-store');
            }
            $app->close();
        }
        if (Review::isRequest($request, $_POST)) {
            (new Review($host))->accept($request, $_POST, time());
            $this->page(Text::_('PLG_SYSTEM_DRACOINSOMNIS_REVIEW_SENT_TITLE'), Text::_('PLG_SYSTEM_DRACOINSOMNIS_REVIEW_SENT_TEXT'), 'review', '', 200);
        }
        $answer = (new Gatekeeper($host))->decide($request, $waf, $host->mode('pace_mode'), ['com_users', '/login', '/registration', '/component/users'], $guest);
        if ($answer !== null) {
            $answer['status'] === 429 ? $this->tooMany($answer['retry']) : $this->deny($answer['why']);
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
        if ($app->isClient('site')) {
            $this->securityHeaders();
        }
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
        $back = (string) $input->server->getString('HTTP_REFERER', 'index.php?option=com_plugins');
        if ($action === 'review') {
            $this->review($input->getInt('id'), $input->getCmd('decision'), $input->getInt('days'));
            $app->redirect($back);
        }
        if ($action === 'test') {
            $this->test();
            $app->redirect($back);
        }
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

    /** Security headers on public pages, when switched on; never one already set. */
    private function securityHeaders(): void
    {
        $app = $this->getApplication();
        $set = array_map(static fn (array $h): string => strtolower((string) $h['name']), $app->getHeaders());
        foreach (SecurityHeaders::wanted($this->host(), $app->isHttpsForced() || \Joomla\CMS\Uri\Uri::getInstance()->isSsl()) as $name => $value) {
            if (!\in_array(strtolower($name), $set, true)) {
                $app->setHeader($name, $value);
            }
        }
    }

    /**
     * Saving the plugin: download the country list when the filter is switched on, and add the block
     * typed in "Block an address or range" (those fields are emptied again).
     */
    public function onExtensionAfterSave(Event $event): void
    {
        [$context, $table] = array_values($event->getArguments()) + [null, null];
        if ($context !== 'com_plugins.plugin' || !\is_object($table) || ($table->element ?? '') !== 'dracoinsomnis') {
            return;
        }
        $params = new \Joomla\Registry\Registry((string) $table->params);
        $host = new JoomlaHost($params);
        $app = $this->getApplication();
        if ($host->setting('geo_mode') !== '' && $host->setting('geo_mode') !== 'off' && Geo::built($host->setting('geo_file')) === '') {
            $error = GeoUpdate::update($host->setting('geo_file'));
            $app->enqueueMessage(Text::_($error === '' ? 'PLG_SYSTEM_DRACOINSOMNIS_GEO_DOWNLOADED' : 'PLG_SYSTEM_DRACOINSOMNIS_GEO_FAILED'), $error === '' ? 'message' : 'warning');
        }
        $value = trim((string) $params->get('block_value', ''));
        if ($value === '') {
            return;
        }
        $done = (new Store())->block('ip', $value, (int) $params->get('block_days', 30), (string) $params->get('block_reason', ''));
        $app->enqueueMessage($done ? Text::sprintf('PLG_SYSTEM_DRACOINSOMNIS_BLOCK_DONE', $value) : Text::_('PLG_SYSTEM_DRACOINSOMNIS_BLOCK_REFUSED'), $done ? 'message' : 'warning');
        $params->set('block_value', '');
        $params->set('block_reason', '');
        $db = \Joomla\CMS\Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
        $json = $params->toString();
        $id = (int) $table->extension_id;
        $db->setQuery($db->getQuery(true)->update($db->quoteName('#__extensions'))->set($db->quoteName('params') . ' = :p')->where($db->quoteName('extension_id') . ' = :id')->bind(':p', $json)->bind(':id', $id, \Joomla\Database\ParameterType::INTEGER))->execute();
    }

    /** A review request: let through (for 1, 7, 30 or 0 = forever days), deny, or mark as an attacker. */
    private function review(int $id, string $decision, int $days): void
    {
        $row = Store::review($id);
        if ($row === null || !\in_array($decision, ['approve', 'deny', 'attacker'], true)) {
            return;
        }
        $fields = json_decode((string) $row['fields'], true);
        $reason = Text::sprintf('PLG_SYSTEM_DRACOINSOMNIS_REVIEW_REASON', \is_array($fields) ? (string) ($fields['email'] ?? '') : '');
        $done = match ($decision) {
            'approve' => Store::allow((string) $row['ip'], $days, $reason),
            'attacker' => (new Store())->block('ip', (string) $row['ip'], 90, $reason, true),
            default => true,
        };
        Store::setVerdict($id, ['approve' => 'approved', 'deny' => 'denied', 'attacker' => 'attacker'][$decision]);
        $this->getApplication()->enqueueMessage(Text::_($done ? 'PLG_SYSTEM_DRACOINSOMNIS_DONE' : 'PLG_SYSTEM_DRACOINSOMNIS_NOT_DONE'), $done ? 'message' : 'error');
    }

    /** Sends the harmless attack-shaped request to the site itself and says what happened. */
    private function test(): void
    {
        $result = TestProbe::run($this->host(), \Joomla\CMS\Uri\Uri::root(), time());
        [$rule, $mode] = array_pad(explode('|', $result, 2), 2, '');
        [$key, $type] = match (true) {
            $rule === 'off' => ['PLG_SYSTEM_DRACOINSOMNIS_TEST_OFF', 'warning'],
            $rule === 'error', $rule === 'unseen' => ['PLG_SYSTEM_DRACOINSOMNIS_TEST_UNREACHABLE', 'warning'],
            $rule === 'upstream' => ['PLG_SYSTEM_DRACOINSOMNIS_TEST_UPSTREAM', 'message'],
            $rule === 'none' => ['PLG_SYSTEM_DRACOINSOMNIS_TEST_NONE', 'error'],
            $mode === 'block' => ['PLG_SYSTEM_DRACOINSOMNIS_TEST_BLOCKED', 'message'],
            default => ['PLG_SYSTEM_DRACOINSOMNIS_TEST_LOGGED', 'message'],
        };
        $this->getApplication()->enqueueMessage(Text::_($key), $type);
    }

    /** No details for the attacker: what matched stays in the log. They may ask for a review. */
    private function deny(string $why): void
    {
        $form = (new Review($this->host()))->form(JoomlaHost::request(), $why, time(), [
            'email' => Text::_('PLG_SYSTEM_DRACOINSOMNIS_REVIEW_EMAIL'),
            'message' => Text::_('PLG_SYSTEM_DRACOINSOMNIS_REVIEW_MESSAGE'),
            'button' => Text::_('PLG_SYSTEM_DRACOINSOMNIS_REVIEW_BUTTON'),
        ]);
        $this->page(Text::_('PLG_SYSTEM_DRACOINSOMNIS_BLOCKED_TITLE'), Text::_('PLG_SYSTEM_DRACOINSOMNIS_BLOCKED_TEXT'), $why, $form, 403);
    }

    private function page(string $title, string $text, string $why, string $form, int $status): void
    {
        if (!headers_sent()) {
            http_response_code($status);
            header('Content-Type: text/html; charset=UTF-8');
            header('Cache-Control: no-store');
            header('X-Robots-Tag: noindex, nofollow');
        }
        echo Firewall::page($title, $text, $why, $form);
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
