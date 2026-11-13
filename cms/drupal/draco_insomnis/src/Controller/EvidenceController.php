<?php

declare(strict_types=1);

namespace Drupal\draco_insomnis\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\draco_insomnis\Store;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * The evidence of one address as CSV, and unblocking (behind a CSRF token).
 */
final class EvidenceController extends ControllerBase {

  public function unblock(int $id): RedirectResponse {
    Store::unblock($id);
    $this->messenger()->addStatus($this->t('Address unblocked.'));
    return new RedirectResponse(Url::fromRoute('draco_insomnis.settings')->toString());
  }

  /** A review request: let through (for 1, 7, 30 or 0 = forever days), deny, or mark as an attacker. */
  public function review(int $id, string $decision, int $days): RedirectResponse {
    $row = Store::review($id);
    if ($row !== NULL) {
      $fields = json_decode((string) $row['fields'], TRUE);
      $reason = (string) $this->t('Review: @email', ['@email' => is_array($fields) ? (string) ($fields['email'] ?? '') : '']);
      $done = match ($decision) {
        'approve' => Store::allow((string) $row['ip'], $days, $reason),
        'attacker' => (new Store())->block('ip', (string) $row['ip'], 90, $reason, TRUE),
        default => TRUE,
      };
      Store::setVerdict($id, ['approve' => 'approved', 'deny' => 'denied', 'attacker' => 'attacker'][$decision]);
      $done ? $this->messenger()->addStatus($this->t('Done.')) : $this->messenger()->addError($this->t('It could not be done for that address.'));
    }
    return new RedirectResponse(Url::fromRoute('draco_insomnis.settings', [], ['fragment' => 'draco-reviews'])->toString());
  }

  /** Sends the harmless attack-shaped request to the site itself and says what happened. */
  public function test(): RedirectResponse {
    $host = \Drupal\draco_insomnis\DrupalHost::get();
    $result = \DracoInsomnis\Core\TestProbe::run($host, Url::fromRoute('<front>', [], ['absolute' => TRUE])->toString(), time());
    [$rule, $mode] = array_pad(explode('|', $result, 2), 2, '');
    if ($rule === 'off') {
      $this->messenger()->addWarning($this->t('The firewall is off: switch it on and save, then test again.'));
    }
    elseif ($rule === 'error' || $rule === 'unseen') {
      $this->messenger()->addWarning($this->t('The test could not reach the site from the server itself (some hostings do not allow it). The firewall may still work: look at the last attempts.'));
    }
    elseif ($rule === 'upstream') {
      $this->messenger()->addStatus($this->t("The test was stopped before it reached Drupal, by the hosting's own firewall. Good: two layers."));
    }
    elseif ($rule === 'none') {
      $this->messenger()->addError($this->t('The test attack was not recognised. Please report it to Draco Insomnis.'));
    }
    else {
      $mode === 'block'
        ? $this->messenger()->addStatus($this->t('Works: a database injection was recognised and blocked (403).'))
        : $this->messenger()->addStatus($this->t('Works: a database injection was recognised. In "Log only" it is written down but not stopped; switch to "Block" when you are ready.'));
    }
    return new RedirectResponse(Url::fromRoute('draco_insomnis.settings')->toString());
  }

  public function csv(string $ip): Response {
    if (filter_var($ip, FILTER_VALIDATE_IP) === FALSE) {
      throw new NotFoundHttpException();
    }
    $out = fopen('php://temp', 'w+');
    fputcsv($out, ['created_at_utc', 'ip', 'remote_addr', 'endpoint', 'verdict', 'score', 'reasons', 'user_agent', 'fields'], ',', '"', '\\');
    foreach (Store::byIp($ip) as $row) {
      fputcsv($out, [$row['created_at'], $row['ip'], $row['remote_addr'], $row['endpoint'], $row['verdict'], $row['score'], $row['reasons'], $row['user_agent'], $row['fields']], ',', '"', '\\');
    }
    rewind($out);
    $csv = (string) stream_get_contents($out);
    fclose($out);
    return new Response($csv, 200, [
      'Content-Type' => 'text/csv; charset=UTF-8',
      'Content-Disposition' => 'attachment; filename="draco-evidence-' . str_replace(':', '-', $ip) . '.csv"',
      'Cache-Control' => 'no-store',
    ]);
  }

}
