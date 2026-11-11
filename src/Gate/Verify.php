<?php

declare(strict_types=1);

namespace DracoInsomnis\Gate;

use DracoInsomnis\Input;
defined('ABSPATH') || exit;

/**
 * The page behind the link in the confirmation mail.
 *
 * Opening the link changes nothing: mail scanners open every link they find, and they would confirm
 * spam on their own. Only pressing the button, which is a POST, delivers the message.
 */
final class Verify
{
    public const ACTION = 'draco_verify';

    public static function register(): void
    {
        // admin-ajax, not admin-post: some themes throw anonymous visitors out of wp-admin, but not out of here.
        add_action('wp_ajax_nopriv_' . self::ACTION, [self::class, 'handle']);
        add_action('wp_ajax_' . self::ACTION, [self::class, 'handle']);
    }

    public static function handle(): void
    {
        nocache_headers();
        $token = isset($_REQUEST['t']) && is_string($_REQUEST['t']) ? sanitize_key(wp_unslash($_REQUEST['t'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the token is the proof
        $row = Store::findPending($token);
        if ($row === null) {
            self::page(__('This link was already used or has expired. If your message did not arrive, send it again from the form.', 'draco-insomnis'));
        }
        if (Input::method() !== 'POST') {
            $ask = [
                'user' => __('Press the button to activate your account.', 'draco-insomnis'),
                'comment' => __('Press the button to send your comment.', 'draco-insomnis'),
            ];
            self::page($ask[$row['kind']] ?? __('Press the button to send your message.', 'draco-insomnis'), $token);
        }
        if (!Store::claim((int) $row['id'])) {
            self::page(__('This link was already used. Thank you.', 'draco-insomnis'));
        }
        self::complete($row);
        if ($row['kind'] === 'comment') {
            self::page(CommentHold::releasedMessage());
        }
        self::page($row['kind'] === 'user' ? __('Your account is now active. Thank you.', 'draco-insomnis') : __('Your message has been sent. Thank you.', 'draco-insomnis'));
    }

    /** @param array<string, mixed> $row */
    public static function complete(array $row): void
    {
        if ($row['kind'] === 'user') {
            RegistrationHold::activate($row);
        } elseif ($row['kind'] === 'comment') {
            CommentHold::release($row);
        } else {
            MailHold::release($row);
        }
        Store::erasePayload((int) $row['id']);
    }

    private static function page(string $text, string $token = ''): void
    {
        $site = (string) get_bloginfo('name');
        $form = '';
        if ($token !== '') {
            $form = '<form method="post" action="' . esc_url(admin_url('admin-ajax.php')) . '">'
                . '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '">'
                . '<input type="hidden" name="t" value="' . esc_attr($token) . '">'
                . '<button type="submit">' . esc_html__('Confirm', 'draco-insomnis') . '</button></form>';
        }
        header('Content-Type: text/html; charset=UTF-8');
        header('X-Robots-Tag: noindex, nofollow');
        echo '<!DOCTYPE html><html lang="' . esc_attr((string) get_bloginfo('language')) . '"><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">'
            . '<title>' . esc_html($site) . '</title><style>'
            . 'body{font:17px/1.5 system-ui,sans-serif;background:#f4f5f7;color:#1d2327;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:20px;box-sizing:border-box}'
            . 'main{background:#fff;border-radius:12px;padding:32px;max-width:440px;width:100%;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}'
            . 'h1{font-size:19px;margin:0 0 12px}button{font:inherit;font-weight:600;background:#2271b1;color:#fff;border:0;border-radius:8px;padding:12px 28px;margin-top:16px;cursor:pointer}'
            . '</style></head><body><main><h1>' . esc_html($site) . '</h1><p>' . esc_html($text) . '</p>' . $form . '</main></body></html>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $form built with esc_*
        exit;
    }
}
