<?php

declare(strict_types=1);

namespace DracoInsomnis\Mail;

defined('ABSPATH') || exit;

/**
 * Designed mail with its plain-text version. Only tables and inline styles: mail clients ignore
 * almost everything else, and the background colour also goes in bgcolor for clients that drop it.
 */
final class Template
{
    public const OPTION_CREDIT = 'draco_mail_credit';
    private const TONES = [
        'blue' => ['#2563eb', '#4f46e5'],
        'green' => ['#059669', '#0d9488'],
        'orange' => ['#ea580c', '#db2777'],
    ];

    /**
     * @param list<string> $paragraphs
     * @param array{tone?: string, code?: string, url?: string, button?: string, after?: list<string>} $options
     */
    public static function send(string $to, string $subject, string $plain, string $title, array $paragraphs, array $options = []): bool
    {
        $alt = static function ($mailer) use ($plain): void {
            $mailer->AltBody = $plain;
        };
        add_action('phpmailer_init', $alt);
        try {
            return (bool) wp_mail($to, $subject, self::html($title, $paragraphs, $options), ['Content-Type: text/html; charset=UTF-8']);
        } finally {
            remove_action('phpmailer_init', $alt);
        }
    }

    /**
     * @param list<string> $paragraphs
     * @param array{tone?: string, code?: string, url?: string, button?: string, after?: list<string>} $options
     */
    public static function html(string $title, array $paragraphs, array $options = []): string
    {
        [$from, $to] = self::TONES[(string) ($options['tone'] ?? 'blue')] ?? self::TONES['blue'];
        $site = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
        $text = static function (array $items): string {
            $out = '';
            foreach ($items as $item) {
                $out .= '<p style="margin:0 0 16px;font-size:16px;line-height:1.6;color:#334155">' . nl2br(esc_html((string) $item)) . '</p>';
            }

            return $out;
        };
        $extra = '';
        if (!empty($options['code'])) {
            $extra .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:8px 0 24px"><tr><td align="center" bgcolor="#eff6ff" style="background:#eff6ff;border:2px dashed ' . esc_attr($from) . ';border-radius:12px;padding:20px">'
                . '<span style="font-family:Consolas,Menlo,monospace;font-size:38px;font-weight:700;letter-spacing:10px;color:' . esc_attr($from) . '">' . esc_html((string) $options['code']) . '</span></td></tr></table>';
        }
        if (!empty($options['url'])) {
            $extra .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:8px 0 24px"><tr><td align="center">'
                . '<a href="' . esc_url((string) $options['url']) . '" style="display:inline-block;background:' . esc_attr($from) . ';color:#ffffff;font-size:16px;font-weight:700;text-decoration:none;padding:14px 32px;border-radius:10px">' . esc_html((string) ($options['button'] ?? __('Open', 'draco-insomnis'))) . '</a></td></tr></table>';
        }
        /* translators: %s: site name */
        $footer = sprintf(__('Automatic message from %s.', 'draco-insomnis'), $site);
        if (get_option(self::OPTION_CREDIT, 'no') === 'yes') {
            $footer .= ' ' . __('Protected by Draco Insomnis · OPNV Systems.', 'draco-insomnis');
        }

        return '<!DOCTYPE html><html lang="' . esc_attr(str_replace('_', '-', determine_locale())) . '"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' . esc_html($title) . '</title></head>'
            . '<body style="margin:0;padding:0;background:#f1f5f9"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#f1f5f9" style="background:#f1f5f9"><tr><td align="center" style="padding:24px 12px">'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">'
            . '<tr><td bgcolor="' . esc_attr($from) . '" style="background:' . esc_attr($from) . ';background-image:linear-gradient(135deg,' . esc_attr($from) . ',' . esc_attr($to) . ');border-radius:16px 16px 0 0;padding:28px 32px">'
            . '<div style="font-size:13px;font-weight:600;letter-spacing:.5px;color:#ffffff;opacity:.9">' . esc_html($site) . '</div>'
            . '<div style="margin-top:6px;font-size:24px;font-weight:700;line-height:1.25;color:#ffffff">' . esc_html($title) . '</div></td></tr>'
            . '<tr><td bgcolor="#ffffff" style="background:#ffffff;padding:32px">' . $text($paragraphs) . $extra . $text((array) ($options['after'] ?? [])) . '</td></tr>'
            . '<tr><td bgcolor="#f8fafc" style="background:#f8fafc;border-radius:0 0 16px 16px;padding:18px 32px;font-size:12px;line-height:1.5;color:#64748b">' . esc_html($footer) . '</td></tr>'
            . '</table></td></tr></table></body></html>';
    }
}
