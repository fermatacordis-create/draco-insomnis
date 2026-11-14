<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Model;

use DracoInsomnis\Core\EventStore;
use DracoInsomnis\Core\Host;
use DracoInsomnis\Core\Request as DracoRequest;
use DracoInsomnis\Core\WafRules;
use Magento\Framework\App\Area;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\DataObject;
use Magento\Framework\Event\ManagerInterface as EventManager;
use Magento\Framework\Mail\Template\TransportBuilder;
use Magento\Store\Model\Store as MagentoStore;

/** The engines in core/ (src/Core of the repository), running in Magento. */
class MagentoHost implements Host
{
    /** JSON bodies larger than this are not inspected (API calls carry no page-sized payloads). */
    private const MAX_JSON = 65536;

    public function __construct(
        private Settings $settings,
        private Store $store,
        private EventManager $events,
        private TransportBuilder $mail
    ) {
    }

    /** One visitor request as plain values. The connection address is read as is. */
    public static function request(HttpRequest $r): DracoRequest
    {
        $clean = static fn ($value): string => is_string($value) ? trim((string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', strip_tags($value))) : '';
        $server = static fn (string $key): string => is_string($r->getServer($key)) ? (string) $r->getServer($key) : '';
        $method = strtoupper($clean($server('REQUEST_METHOD'))) ?: 'GET';
        $body = $method === 'GET' || $method === 'HEAD' ? [] : (array) $r->getPost()->toArray();
        // The REST API and GraphQL read JSON, not form fields: inspect it too.
        if ($body === [] && $method !== 'GET' && str_contains(strtolower($server('CONTENT_TYPE')), 'json')) {
            $raw = (string) $r->getContent();
            $json = strlen($raw) <= self::MAX_JSON ? json_decode($raw, true) : null;
            $body = is_array($json) ? $json : [];
        }
        $post = [];
        foreach ((array) $r->getPost()->toArray() as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $post[$name] = $clean($value);
            }
        }
        $uri = $server('REQUEST_URI') ?: '/';

        return new DracoRequest(
            $method,
            rawurldecode((string) parse_url($uri, PHP_URL_PATH)),
            urldecode((string) parse_url($uri, PHP_URL_QUERY)),
            WafRules::flatten(array_merge((array) $r->getQuery()->toArray(), $body)),
            $post,
            $clean($server('HTTP_USER_AGENT')),
            $server('HTTP_USER_AGENT'),
            $clean($server('REMOTE_ADDR')),
            $clean($server('HTTP_CF_CONNECTING_IP')),
            $clean($server('HTTP_X_FORWARDED_FOR')),
            $clean((string) filter_var($server('HTTP_REFERER'), FILTER_SANITIZE_URL)),
        );
    }

    public function secret(): string
    {
        return $this->settings->secret();
    }

    public function setting(string $name): string
    {
        return $this->settings->setting($name);
    }

    public function adminIps(): array
    {
        return $this->store->adminIps();
    }

    public function bump(string $key, int $ttl): int
    {
        return $this->store->bump($key, $ttl);
    }

    public function recall(string $key): ?string
    {
        return $this->store->recall($key);
    }

    public function remember(string $key, string $value, int $ttl): void
    {
        $this->store->remember($key, $value, $ttl);
    }

    /**
     * Shop code can change a value through the draco_insomnis_filter event: its "transport" has
     * name, value and args; change value.
     */
    public function filter(string $name, $value, ...$args)
    {
        $transport = new DataObject(['name' => $name, 'value' => $value, 'args' => $args]);
        $this->events->dispatch('draco_insomnis_filter', ['transport' => $transport]);

        return $transport->getData('value');
    }

    public function text(string $id, int $number): string
    {
        return match ($id) {
            'waf_block' => (string) __('Firewall: %1 attacks in 10 minutes', $number),
            'pwd_short' => (string) __('The password must have at least %1 characters.', $number),
            'pwd_breached' => (string) __('This password appears in known data breaches, so attackers try it first. Please choose another one.'),
            'review_subject' => (string) __('[%1] Someone asks you to review a firewall block', $this->settings->shopName()),
            'review_body' => (string) __('A visitor stopped by the firewall asks for a review. To let them through or not: bin/magento draco:reviews'),
            default => (string) __('Automatic: %1 bot attempts in 24 h', $number),
        };
    }

    public function notifyOwner(string $subject, string $body): void
    {
        $to = $this->settings->notifyEmail();
        if ($to === '') {
            return;
        }
        try {
            $this->mail->setTemplateIdentifier('draco_insomnis_notice')
                ->setTemplateOptions(['area' => Area::AREA_ADMINHTML, 'store' => MagentoStore::DEFAULT_STORE_ID])
                ->setTemplateVars(['subject' => $subject, 'message' => $body])
                ->setFromByScope('general')
                ->addTo($to)
                ->getTransport()
                ->sendMessage();
        } catch (\Throwable $e) {
            // A notice that cannot be sent never breaks the visitor's request.
        }
    }

    public function events(): EventStore
    {
        return $this->store;
    }
}
