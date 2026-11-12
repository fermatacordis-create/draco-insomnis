<?php

declare(strict_types=1);

namespace Drupal\draco_insomnis;

use DracoInsomnis\Core\EventStore;

/**
 * Evidence, block list and short-lived counters, in the module's own tables.
 *
 * Never stores passwords or anything beyond the fields the engines pass.
 */
final class Store implements EventStore {

  public const KEEP_DAYS = 90;
  public const BLOCK_DAYS = [7, 15, 30, 90];
  /** One flood must not fill the database: past this, attempts from that IP in the hour are only counted. */
  private const MAX_ROWS_PER_IP_HOUR = 30;

  private static function db(): \Drupal\Core\Database\Connection {
    return \Drupal::database();
  }

  private static function now(): string {
    return gmdate('Y-m-d H:i:s');
  }

  /* Counters and short-lived values. */

  public static function bump(string $key, int $ttl): int {
    $k = substr($key, 0, 190);
    $now = time();
    $until = $now + $ttl;
    $updated = self::db()->update('draco_insomnis_cache')
      ->expression('n', 'CASE WHEN expires < :now THEN 1 ELSE n + 1 END', [':now' => $now])
      ->fields(['expires' => $until])
      ->condition('k', $k)
      ->execute();
    if (!$updated) {
      try {
        self::db()->insert('draco_insomnis_cache')->fields(['k' => $k, 'n' => 1, 'v' => '', 'expires' => $until])->execute();
        return 1;
      }
      catch (\Exception $e) {
        // Another request inserted it in between: count on that row.
        return self::bump($key, $ttl);
      }
    }
    return (int) self::db()->select('draco_insomnis_cache', 'c')->fields('c', ['n'])->condition('k', $k)->execute()->fetchField();
  }

  public static function recall(string $key): ?string {
    $value = self::db()->select('draco_insomnis_cache', 'c')->fields('c', ['v'])
      ->condition('k', substr($key, 0, 190))->condition('expires', time(), '>=')->execute()->fetchField();
    return $value === FALSE ? NULL : (string) $value;
  }

  public static function remember(string $key, string $value, int $ttl): void {
    self::db()->merge('draco_insomnis_cache')
      ->key('k', substr($key, 0, 190))
      ->fields(['v' => substr($value, 0, 255), 'n' => 0, 'expires' => time() + $ttl])
      ->execute();
  }

  /* Evidence and block list. */

  public function log(string $ip, string $remoteAddr, string $endpoint, array $result, string $userAgent, array $fields): void {
    if (self::bump('draco_rows_' . md5($ip), 3600) > self::MAX_ROWS_PER_IP_HOUR) {
      return;
    }
    self::db()->insert('draco_insomnis_events')->fields([
      'created_at' => self::now(),
      'ip' => $ip,
      'remote_addr' => $remoteAddr,
      'endpoint' => substr($endpoint, 0, 40),
      'score' => min(65535, max(0, (int) $result['score'])),
      'verdict' => (string) $result['verdict'],
      'reasons' => substr(implode(',', $result['reasons']), 0, 190),
      'user_agent' => substr($userAgent, 0, 255),
      'fields' => (string) json_encode($fields, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
    ])->execute();
  }

  public function botAttemptsSince(string $ip, int $seconds): int {
    return (int) self::db()->select('draco_insomnis_events', 'e')
      ->condition('ip', $ip)->condition('verdict', 'bot')->condition('created_at', gmdate('Y-m-d H:i:s', time() - $seconds), '>')
      ->countQuery()->execute()->fetchField();
  }

  public function isBlocked(string $email, string $ip): bool {
    $query = self::db()->select('draco_insomnis_blocks', 'b')->fields('b', ['id']);
    $match = $query->orConditionGroup()
      ->condition($query->andConditionGroup()->condition('kind', 'email')->condition('value', strtolower($email)))
      ->condition($query->andConditionGroup()->condition('kind', 'ip')->condition('value', strtolower($ip)));
    return (bool) $query->condition('until_at', self::now(), '>')->condition($match)->range(0, 1)->execute()->fetchField();
  }

  /**
   * Never blocks an administrator's e-mail or an address an administrator used recently.
   */
  public function block(string $kind, string $value, int $days, string $reason, bool $automatic = FALSE): bool {
    $value = strtolower(trim($value));
    if (!in_array($days, self::BLOCK_DAYS, TRUE)) {
      return FALSE;
    }
    if ($kind === 'ip') {
      if (filter_var($value, FILTER_VALIDATE_IP) === FALSE || in_array($value, DrupalHost::get()->adminIps(), TRUE)) {
        return FALSE;
      }
    }
    elseif ($kind === 'email') {
      $users = \Drupal::entityTypeManager()->getStorage('user')->loadByProperties(['mail' => $value]);
      $user = reset($users);
      if (filter_var($value, FILTER_VALIDATE_EMAIL) === FALSE || ($user && $user->hasPermission('administer users'))) {
        return FALSE;
      }
    }
    else {
      return FALSE;
    }
    self::db()->insert('draco_insomnis_blocks')->fields([
      'kind' => $kind,
      'value' => $value,
      'reason' => substr($reason, 0, 190),
      'created_at' => self::now(),
      'until_at' => gmdate('Y-m-d H:i:s', time() + $days * 86400),
    ])->execute();
    return TRUE;
  }

  public static function unblock(int $id): void {
    self::db()->delete('draco_insomnis_blocks')->condition('id', $id)->execute();
  }

  public static function recent(int $limit = 50): array {
    return self::db()->select('draco_insomnis_events', 'e')->fields('e')->orderBy('id', 'DESC')->range(0, $limit)->execute()->fetchAll(\PDO::FETCH_ASSOC);
  }

  public static function activeBlocks(): array {
    return self::db()->select('draco_insomnis_blocks', 'b')->fields('b')->condition('until_at', self::now(), '>')
      ->orderBy('until_at', 'DESC')->range(0, 200)->execute()->fetchAll(\PDO::FETCH_ASSOC);
  }

  /**
   * Everything from one address, oldest first, for an abuse report.
   */
  public static function byIp(string $ip): array {
    $query = self::db()->select('draco_insomnis_events', 'e')->fields('e');
    $either = $query->orConditionGroup()->condition('ip', $ip)->condition('remote_addr', $ip);
    return $query->condition($either)->orderBy('id', 'ASC')->range(0, 2000)->execute()->fetchAll(\PDO::FETCH_ASSOC);
  }

  public static function cleanup(): void {
    self::db()->delete('draco_insomnis_events')->condition('created_at', gmdate('Y-m-d H:i:s', time() - self::KEEP_DAYS * 86400), '<')->execute();
    self::db()->delete('draco_insomnis_blocks')->condition('until_at', self::now(), '<')->execute();
    self::db()->delete('draco_insomnis_cache')->condition('expires', time(), '<')->execute();
  }

}
