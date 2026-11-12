<?php

/**
 * @package     Draco Insomnis for Joomla
 * @copyright   (C) 2026 Notorius Vision
 * @license     GNU General Public License version 2 or later
 */

namespace Notorius\Plugin\System\DracoInsomnis;

use DracoInsomnis\Core\EventStore;
use Joomla\CMS\Factory;
use Joomla\Database\DatabaseInterface;
use Joomla\Database\ParameterType;

\defined('_JEXEC') or die;

/**
 * Evidence, block list and short-lived counters, in the plugin's own tables.
 * Never stores passwords or anything beyond the fields the engines pass.
 */
final class Store implements EventStore
{
    public const KEEP_DAYS = 90;
    public const BLOCK_DAYS = [7, 15, 30, 90];
    /** One flood must not fill the database: past this, attempts from that IP in the hour are only counted. */
    private const MAX_ROWS_PER_IP_HOUR = 30;

    private static function db(): DatabaseInterface
    {
        return Factory::getContainer()->get(DatabaseInterface::class);
    }

    private static function now(): string
    {
        return gmdate('Y-m-d H:i:s');
    }

    /* Counters and short-lived values. */

    public static function bump(string $key, int $ttl): int
    {
        $db = self::db();
        $k = substr($key, 0, 190);
        $now = time();
        $until = $now + $ttl;
        $update = $db->getQuery(true)
            ->update($db->quoteName('#__dracoinsomnis_cache'))
            ->set($db->quoteName('n') . ' = CASE WHEN ' . $db->quoteName('expires') . ' < ' . $now . ' THEN 1 ELSE ' . $db->quoteName('n') . ' + 1 END')
            ->set($db->quoteName('expires') . ' = ' . $until)
            ->where($db->quoteName('k') . ' = :k')
            ->bind(':k', $k);
        $db->setQuery($update)->execute();
        if ($db->getAffectedRows() < 1) {
            try {
                $row = (object) ['k' => $k, 'n' => 1, 'v' => '', 'expires' => $until];
                $db->insertObject('#__dracoinsomnis_cache', $row);

                return 1;
            } catch (\RuntimeException $e) {
                // Another request inserted it in between: count on that row.
                return self::bump($key, $ttl);
            }
        }
        $select = $db->getQuery(true)->select($db->quoteName('n'))->from($db->quoteName('#__dracoinsomnis_cache'))
            ->where($db->quoteName('k') . ' = :k')->bind(':k', $k);

        return (int) $db->setQuery($select)->loadResult();
    }

    public static function recall(string $key): ?string
    {
        $db = self::db();
        $k = substr($key, 0, 190);
        $now = time();
        $query = $db->getQuery(true)->select($db->quoteName('v'))->from($db->quoteName('#__dracoinsomnis_cache'))
            ->where($db->quoteName('k') . ' = :k')->where($db->quoteName('expires') . ' >= :now')
            ->bind(':k', $k)->bind(':now', $now, ParameterType::INTEGER);
        $value = $db->setQuery($query)->loadResult();

        return $value === null ? null : (string) $value;
    }

    public static function remember(string $key, string $value, int $ttl): void
    {
        $db = self::db();
        $k = substr($key, 0, 190);
        $v = substr($value, 0, 255);
        $until = time() + $ttl;
        $db->setQuery(
            'INSERT INTO ' . $db->quoteName('#__dracoinsomnis_cache') . ' (k, n, v, expires) VALUES (' . $db->quote($k) . ', 0, ' . $db->quote($v) . ', ' . $until . ')'
            . ' ON DUPLICATE KEY UPDATE v = ' . $db->quote($v) . ', expires = ' . $until
        )->execute();
    }

    /* Evidence and block list. */

    public function log(string $ip, string $remoteAddr, string $endpoint, array $result, string $userAgent, array $fields): void
    {
        if (self::bump('draco_rows_' . md5($ip), 3600) > self::MAX_ROWS_PER_IP_HOUR) {
            return;
        }
        $row = (object) [
            'created_at' => self::now(),
            'ip' => $ip,
            'remote_addr' => $remoteAddr,
            'endpoint' => substr($endpoint, 0, 40),
            'score' => min(65535, max(0, (int) $result['score'])),
            'verdict' => (string) $result['verdict'],
            'reasons' => substr(implode(',', $result['reasons']), 0, 190),
            'user_agent' => substr($userAgent, 0, 255),
            'fields' => (string) json_encode($fields, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        ];
        self::db()->insertObject('#__dracoinsomnis_events', $row);
    }

    public function botAttemptsSince(string $ip, int $seconds): int
    {
        $db = self::db();
        $since = gmdate('Y-m-d H:i:s', time() - $seconds);
        $query = $db->getQuery(true)->select('COUNT(*)')->from($db->quoteName('#__dracoinsomnis_events'))
            ->where($db->quoteName('ip') . ' = :ip')->where($db->quoteName('verdict') . " = 'bot'")->where($db->quoteName('created_at') . ' > :since')
            ->bind(':ip', $ip)->bind(':since', $since);

        return (int) $db->setQuery($query)->loadResult();
    }

    public function isBlocked(string $email, string $ip): bool
    {
        $db = self::db();
        $now = self::now();
        $email = strtolower($email);
        $ip = strtolower($ip);
        $query = $db->getQuery(true)->select($db->quoteName('id'))->from($db->quoteName('#__dracoinsomnis_blocks'))
            ->where($db->quoteName('until_at') . ' > :now')
            ->where('((' . $db->quoteName('kind') . " = 'email' AND " . $db->quoteName('value') . ' = :email) OR (' . $db->quoteName('kind') . " = 'ip' AND " . $db->quoteName('value') . ' = :ip))')
            ->bind(':now', $now)->bind(':email', $email)->bind(':ip', $ip)
            ->setLimit(1);

        return (bool) $db->setQuery($query)->loadResult();
    }

    /** Never blocks an administrator's e-mail or an address an administrator used recently. */
    public function block(string $kind, string $value, int $days, string $reason, bool $automatic = false): bool
    {
        $value = strtolower(trim($value));
        if (!\in_array($days, self::BLOCK_DAYS, true)) {
            return false;
        }
        if ($kind === 'ip') {
            if (filter_var($value, FILTER_VALIDATE_IP) === false) {
                return false;
            }
            $list = json_decode((string) self::recall('draco_admin_ips'), true);
            if (\is_array($list) && \in_array($value, $list, true)) {
                return false;
            }
        } elseif ($kind === 'email') {
            if (filter_var($value, FILTER_VALIDATE_EMAIL) === false || self::isAdminEmail($value)) {
                return false;
            }
        } else {
            return false;
        }
        $row = (object) [
            'kind' => $kind,
            'value' => $value,
            'reason' => substr($reason, 0, 190),
            'created_at' => self::now(),
            'until_at' => gmdate('Y-m-d H:i:s', time() + $days * 86400),
        ];

        return self::db()->insertObject('#__dracoinsomnis_blocks', $row);
    }

    private static function isAdminEmail(string $email): bool
    {
        $db = self::db();
        $query = $db->getQuery(true)->select($db->quoteName('id'))->from($db->quoteName('#__users'))
            ->where('LOWER(' . $db->quoteName('email') . ') = :email')->bind(':email', $email)->setLimit(1);
        $id = (int) $db->setQuery($query)->loadResult();

        return $id > 0 && Factory::getContainer()->get(\Joomla\CMS\User\UserFactoryInterface::class)->loadUserById($id)->authorise('core.login.admin');
    }

    public static function unblock(int $id): void
    {
        $db = self::db();
        $db->setQuery($db->getQuery(true)->delete($db->quoteName('#__dracoinsomnis_blocks'))->where($db->quoteName('id') . ' = :id')->bind(':id', $id, ParameterType::INTEGER))->execute();
    }

    public static function recent(int $limit = 50): array
    {
        $db = self::db();
        $query = $db->getQuery(true)->select('*')->from($db->quoteName('#__dracoinsomnis_events'))->order($db->quoteName('id') . ' DESC')->setLimit($limit);

        return (array) $db->setQuery($query)->loadAssocList();
    }

    public static function activeBlocks(): array
    {
        $db = self::db();
        $now = self::now();
        $query = $db->getQuery(true)->select('*')->from($db->quoteName('#__dracoinsomnis_blocks'))
            ->where($db->quoteName('until_at') . ' > :now')->bind(':now', $now)->order($db->quoteName('until_at') . ' DESC')->setLimit(200);

        return (array) $db->setQuery($query)->loadAssocList();
    }

    /** Everything from one address, oldest first, for an abuse report. */
    public static function byIp(string $ip): array
    {
        $db = self::db();
        $query = $db->getQuery(true)->select('*')->from($db->quoteName('#__dracoinsomnis_events'))
            ->where('(' . $db->quoteName('ip') . ' = :ip OR ' . $db->quoteName('remote_addr') . ' = :ip2)')
            ->bind(':ip', $ip)->bind(':ip2', $ip)->order($db->quoteName('id') . ' ASC')->setLimit(2000);

        return (array) $db->setQuery($query)->loadAssocList();
    }

    /** Joomla's own scheduler is optional: about one request in two hundred tidies up. */
    public static function maybeCleanup(): void
    {
        if (random_int(1, 200) !== 1) {
            return;
        }
        $db = self::db();
        $old = gmdate('Y-m-d H:i:s', time() - self::KEEP_DAYS * 86400);
        $now = self::now();
        $time = time();
        $db->setQuery($db->getQuery(true)->delete($db->quoteName('#__dracoinsomnis_events'))->where($db->quoteName('created_at') . ' < :old')->bind(':old', $old))->execute();
        $db->setQuery($db->getQuery(true)->delete($db->quoteName('#__dracoinsomnis_blocks'))->where($db->quoteName('until_at') . ' < :now')->bind(':now', $now))->execute();
        $db->setQuery($db->getQuery(true)->delete($db->quoteName('#__dracoinsomnis_cache'))->where($db->quoteName('expires') . ' < :t')->bind(':t', $time, ParameterType::INTEGER))->execute();
    }
}
