<?php

/**
 * @package     Draco Insomnis for Joomla
 * @copyright   (C) 2026 Notorius Vision
 * @license     GNU General Public License version 2 or later
 */

namespace Notorius\Plugin\System\DracoInsomnis\Field;

use Joomla\CMS\Form\FormField;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Session\Session;
use Notorius\Plugin\System\DracoInsomnis\Store;

\defined('_JEXEC') or die;

/** The block list (with unblock) and the last suspicious attempts (with a CSV per address). */
final class DracoevidenceField extends FormField
{
    protected $type = 'Dracoevidence';

    protected function getLabel()
    {
        return '';
    }

    private static function h(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    }

    private static function link(array $params): string
    {
        return 'index.php?' . http_build_query(['option' => 'com_ajax', 'group' => 'system', 'plugin' => 'dracoinsomnis', 'format' => 'raw'] + $params + [Session::getFormToken() => 1]);
    }

    private static function summary(): string
    {
        $sum = \DracoInsomnis\Core\Summary::waf(Store::wafRows(7 * 86400));
        $html = '<h3 class="mt-4">' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_SUMMARY')) . '</h3><p>' . self::h(Text::sprintf('PLG_SYSTEM_DRACOINSOMNIS_SUMMARY_LINE', $sum['total'], $sum['blocked'])) . '</p>';
        $parts = [];
        foreach ($sum['rules'] as $rule => $n) {
            $parts[] = self::h(str_replace('waf_', '', (string) $rule)) . ': ' . (int) $n;
        }
        if ($parts !== []) {
            $html .= '<p><strong>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_SUMMARY_WHAT')) . '</strong> ' . implode(' · ', $parts) . '</p>';
        }
        $parts = [];
        foreach ($sum['ips'] as $ip => $n) {
            $parts[] = '<code>' . self::h((string) $ip) . '</code>: ' . (int) $n;
        }
        if ($parts !== []) {
            $html .= '<p><strong>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_SUMMARY_IPS')) . '</strong> ' . implode(' · ', $parts) . '</p>';
        }

        return $html . '<p><a class="btn btn-primary" id="draco-test" href="' . self::h(self::link(['action' => 'test'])) . '">' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_TEST')) . '</a> '
            . '<small class="text-muted">' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_TEST_HELP')) . '</small></p>';
    }

    private static function reviews(): string
    {
        $html = '<h3 class="mt-4" id="draco-reviews">' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_REVIEWS')) . '</h3><p class="text-muted">' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_REVIEWS_HELP')) . '</p>';
        $rows = Store::reviews(50);
        if ($rows === []) {
            return $html . '<p>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_NO_REVIEWS')) . '</p>';
        }
        $states = ['approved' => 'PLG_SYSTEM_DRACOINSOMNIS_REVIEW_APPROVED', 'denied' => 'PLG_SYSTEM_DRACOINSOMNIS_REVIEW_DENIED', 'attacker' => 'PLG_SYSTEM_DRACOINSOMNIS_REVIEW_ATTACKER'];
        $html .= '<table class="table table-sm"><thead><tr><th>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_COL_DATE')) . '</th><th>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_COL_IP')) . '</th><th>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_COL_EMAIL')) . '</th><th>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_COL_MESSAGE')) . '</th><th></th></tr></thead><tbody>';
        foreach ($rows as $row) {
            $fields = json_decode((string) $row['fields'], true);
            $fields = \is_array($fields) ? $fields : [];
            if ($row['verdict'] === 'pending') {
                $go = static fn (string $key, string $decision, int $days = 0): string => '<a class="btn btn-sm btn-secondary me-1" href="' . self::h(self::link(['action' => 'review', 'id' => (int) $row['id'], 'decision' => $decision, 'days' => $days])) . '">' . self::h(Text::_($key)) . '</a>';
                $actions = $go('PLG_SYSTEM_DRACOINSOMNIS_REVIEW_1', 'approve', 1) . $go('PLG_SYSTEM_DRACOINSOMNIS_REVIEW_7', 'approve', 7) . $go('PLG_SYSTEM_DRACOINSOMNIS_REVIEW_30', 'approve', 30)
                    . $go('PLG_SYSTEM_DRACOINSOMNIS_FOREVER', 'approve', 0) . $go('PLG_SYSTEM_DRACOINSOMNIS_REVIEW_DENY', 'deny') . $go('PLG_SYSTEM_DRACOINSOMNIS_REVIEW_ATTACKER_BTN', 'attacker');
            } else {
                $actions = self::h(Text::_($states[(string) $row['verdict']] ?? 'JNONE'));
            }
            $html .= '<tr><td>' . self::h((string) $row['created_at']) . '</td><td><code>' . self::h((string) $row['ip']) . '</code></td><td>' . self::h((string) ($fields['email'] ?? '')) . '</td><td><small>' . self::h((string) ($fields['referer'] ?? '')) . '</small></td><td class="text-end">' . $actions . '</td></tr>';
        }

        return $html . '</tbody></table>';
    }

    protected function getInput()
    {
        $html = self::summary() . self::reviews();
        $html .= '<h3 class="mt-4">' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_BLOCKS')) . '</h3>';
        $blocks = Store::activeBlocks();
        if ($blocks === []) {
            $html .= '<p>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_NO_BLOCKS')) . '</p>';
        } else {
            $html .= '<table class="table table-sm"><thead><tr><th>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_COL_VALUE')) . '</th><th>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_COL_REASON')) . '</th><th>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_COL_UNTIL')) . '</th><th></th></tr></thead><tbody>';
            foreach ($blocks as $row) {
                $html .= '<tr><td><code>' . self::h((string) $row['value']) . '</code></td><td>' . self::h((string) $row['reason']) . '</td><td>' . self::h(\DracoInsomnis\Core\Blocklist::isForever((string) $row['until_at']) ? Text::_('PLG_SYSTEM_DRACOINSOMNIS_FOREVER') : (string) $row['until_at']) . '</td>'
                    . '<td class="text-end"><a class="btn btn-sm btn-secondary" href="' . self::h(self::link(['action' => 'unblock', 'id' => (int) $row['id']])) . '">' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_UNBLOCK')) . '</a></td></tr>';
            }
            $html .= '</tbody></table>';
        }

        $html .= '<h3 class="mt-4">' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_EVENTS')) . '</h3><p class="text-muted">' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_EVENTS_HELP')) . '</p>';
        $events = Store::recent(50);
        if ($events === []) {
            return $html . '<p>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_NO_EVENTS')) . '</p>';
        }
        $html .= '<div class="table-responsive"><table class="table table-sm"><thead><tr><th>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_COL_DATE')) . '</th><th>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_COL_IP')) . '</th><th>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_COL_WHERE')) . '</th><th>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_COL_VERDICT')) . '</th><th>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_COL_SIGNS')) . '</th><th>' . self::h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_COL_DATA')) . '</th><th></th></tr></thead><tbody>';
        foreach ($events as $row) {
            $fields = json_decode((string) $row['fields'], true);
            $data = \is_array($fields) ? implode(' · ', array_filter(array_map('strval', $fields))) : '';
            // The full text is in the CSV; the table only needs enough to recognise the attempt.
            $data = mb_strimwidth($data, 0, 70, '…');
            $badge = $row['verdict'] === 'bot' ? 'bg-danger' : 'bg-warning text-dark';
            $html .= '<tr><td>' . self::h((string) $row['created_at']) . '</td><td><code>' . self::h((string) $row['ip']) . '</code></td><td>' . self::h((string) $row['endpoint']) . '</td>'
                . '<td><span class="badge ' . $badge . '">' . self::h((string) $row['verdict']) . '</span></td><td><small>' . self::h(str_replace(',', ', ', (string) $row['reasons'])) . '</small></td>'
                . '<td style="min-width:14em"><small>' . self::h($data) . '</small></td><td class="text-end"><a class="btn btn-sm btn-secondary" href="' . self::h(self::link(['action' => 'csv', 'ip' => (string) $row['ip']])) . '">CSV</a></td></tr>';
        }

        return $html . '</tbody></table></div>';
    }
}
