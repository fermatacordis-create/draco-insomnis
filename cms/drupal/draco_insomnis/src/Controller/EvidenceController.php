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
