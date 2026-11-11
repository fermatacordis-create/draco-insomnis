<?php

declare(strict_types=1);

namespace DracoInsomnis\Gate;

use DracoInsomnis\Shield\Guard;
use DracoInsomnis\Shield\Store as Blocks;

defined('ABSPATH') || exit;

/**
 * Holds the mail a public form tries to send until its sender confirms their address.
 *
 * Every form plugin ends in wp_mail(), so the message is held there, exactly as the form built it.
 * Only requests recognised as a form submission are touched: password resets, orders and any other
 * mail pass untouched, and so does a form whose sender address cannot be found.
 */
final class MailHold
{
    private const MAX_ATTACHMENT_BYTES = 8388608;
    private static int $submission = 0;
    private static bool $held = false;
    private static bool $dropped = false;
    private static bool $releasing = false;

    public static function register(): void
    {
        add_filter('pre_wp_mail', [self::class, 'intercept'], 10, 2);
        add_filter('wpcf7_feedback_response', [self::class, 'cf7Response'], 10, 2);
        add_filter('wpforms_frontend_confirmation_message', [self::class, 'plainNotice'], 99);
        // WPForms can send from a later background task, where the form request is gone.
        add_filter('wpforms_tasks_entry_emails_trigger_send_same_process', '__return_true');
        add_action('init', [self::class, 'watchOutput'], 1);
    }

    /** @param null|bool $return @param array<string, mixed> $atts */
    public static function intercept($return, array $atts)
    {
        if ($return !== null || self::$releasing || Mailer::isSending() || is_user_logged_in()) {
            return $return;
        }
        $context = self::context();
        if ($context === '') {
            return $return;
        }
        if (self::$dropped) {
            return true;
        }
        if (self::$submission === 0) {
            $email = self::senderEmail($atts);
            if ($email === '') {
                return $return;
            }
            $ip = Guard::clientIp();
            self::$held = true;
            // A blocked sender gets the same "almost done" answer, so they cannot tell.
            if (Blocks::isBlocked($email, $ip) || !Mailer::allow($email, $ip)) {
                self::$dropped = true;

                return true;
            }
            $created = Store::create('form', $context, $email, $ip);
            if ($created === null) {
                self::$held = false;

                return $return;
            }
            self::$submission = $created['id'];
            Mailer::send($email, $created['token'], 'form');
        }
        Store::appendMail(self::$submission, self::pack($atts));

        return true;
    }

    public static function context(): string
    {
        // phpcs:disable WordPress.Security.NonceVerification.Missing -- only recognises which form is being sent
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '');
        $action = isset($_POST['action']) && is_string($_POST['action']) ? $_POST['action'] : '';
        $context = '';
        if (str_contains($uri, '/contact-form-7/v1/contact-forms/') || isset($_POST['_wpcf7'])) {
            $context = 'cf7';
        } elseif (isset($_POST['wpforms'])) {
            $context = 'wpforms';
        } elseif ($action === 'elementor_pro_forms_send_form') {
            $context = 'elementor';
        } elseif (in_array($action, ['rhea_inquiry_send_message', 'rhea_schedule_a_tour', 'rhea_schedule_tour_form_mail', 'rhea_send_message_to_agent'], true)) {
            $context = 'realhomes';
        } else {
            foreach (array_keys($_POST) as $key) {
                if (str_starts_with((string) $key, 'et_pb_contactform_submit_')) {
                    $context = 'divi';
                    break;
                }
            }
        }
        // phpcs:enable

        return (string) apply_filters('draco_insomnis_form_context', $context);
    }

    /** @param array<string, mixed> $atts */
    public static function senderEmail(array $atts): string
    {
        $headers = $atts['headers'] ?? [];
        $lines = is_array($headers) ? $headers : explode("\n", str_replace("\r\n", "\n", (string) $headers));
        foreach ($lines as $line) {
            if (stripos((string) $line, 'reply-to:') === 0 && preg_match('/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i', (string) $line, $found) === 1) {
                return strtolower($found[0]);
            }
        }

        return self::firstEmail($_POST, 0); // phpcs:ignore WordPress.Security.NonceVerification.Missing
    }

    /** @param array<mixed> $values */
    private static function firstEmail(array $values, int $depth): string
    {
        foreach ($values as $value) {
            if (is_string($value) && strlen($value) < 190 && is_email(trim($value))) {
                return strtolower(trim($value));
            }
            if (is_array($value) && $depth < 4) {
                $found = self::firstEmail($value, $depth + 1);
                if ($found !== '') {
                    return $found;
                }
            }
        }

        return '';
    }

    /**
     * Attachments are stored too: form plugins delete their temporary files when the request ends.
     *
     * @param array<string, mixed> $atts
     * @return array<string, mixed>
     */
    private static function pack(array $atts): array
    {
        $files = [];
        $total = 0;
        $list = $atts['attachments'] ?? [];
        $list = is_array($list) ? $list : array_filter(explode("\n", (string) $list));
        foreach ($list as $path) {
            $size = is_readable((string) $path) ? (int) filesize((string) $path) : 0;
            if ($size > 0 && $total + $size <= self::MAX_ATTACHMENT_BYTES) {
                $total += $size;
                $files[] = ['name' => basename((string) $path), 'data' => base64_encode((string) file_get_contents((string) $path))]; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
            }
        }

        return [
            'to' => $atts['to'] ?? '',
            'subject' => (string) ($atts['subject'] ?? ''),
            'message' => (string) ($atts['message'] ?? ''),
            'headers' => $atts['headers'] ?? [],
            'files' => $files,
        ];
    }

    /** @param array<string, mixed> $row */
    public static function release(array $row): void
    {
        $mails = json_decode((string) $row['payload'], true);
        self::$releasing = true;
        $dir = '';
        try {
            foreach (is_array($mails) ? $mails : [] as $mail) {
                $paths = [];
                foreach ((array) ($mail['files'] ?? []) as $file) {
                    $dir = $dir !== '' ? $dir : self::tempDir();
                    $path = $dir . '/' . sanitize_file_name((string) $file['name']);
                    file_put_contents($path, (string) base64_decode((string) $file['data'])); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
                    $paths[] = $path;
                }
                $message = (string) ($mail['message'] ?? '');
                if (!self::isToSender($mail, (string) $row['email'])) {
                    $message .= self::footer($mail, (int) $row['id']);
                }
                wp_mail($mail['to'] ?? '', (string) ($mail['subject'] ?? ''), $message, $mail['headers'] ?? [], $paths);
                array_map('unlink', array_filter($paths, 'is_file'));
            }
        } finally {
            self::$releasing = false;
            if ($dir !== '') {
                @rmdir($dir); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
            }
        }
    }

    private static function tempDir(): string
    {
        $dir = get_temp_dir() . 'draco-gate-' . wp_generate_password(16, false);
        wp_mkdir_p($dir);

        return $dir;
    }

    /** @param array<string, mixed> $mail */
    private static function isToSender(array $mail, string $email): bool
    {
        $to = is_array($mail['to'] ?? null) ? implode(',', $mail['to']) : (string) ($mail['to'] ?? '');

        return stripos($to, $email) !== false;
    }

    /** A link for the site owner, under the delivered message, to block the sender if it is spam. @param array<string, mixed> $mail */
    private static function footer(array $mail, int $id): string
    {
        $url = admin_url('admin.php?page=' . Admin::SLUG . '&block=' . $id);
        $label = __('Spam? Block this sender', 'draco-insomnis');
        $headers = is_array($mail['headers'] ?? null) ? implode("\n", $mail['headers']) : (string) ($mail['headers'] ?? '');
        if (stripos($headers, 'text/html') !== false) {
            return '<p style="font-size:12px"><a href="' . esc_url($url) . '">' . esc_html($label) . '</a></p>';
        }

        return "\n\n--\n$label: $url\n";
    }

    /**
     * @param array<string, mixed> $response
     * @param array<string, mixed> $result
     * @return array<string, mixed>
     */
    public static function cf7Response($response, $result): array
    {
        $response = (array) $response;
        if (self::$held && ($response['status'] ?? '') === 'mail_sent') {
            $response['message'] = self::notice();
        }

        return $response;
    }

    /** @param string $message */
    public static function plainNotice($message): string
    {
        return self::$held ? '<p>' . esc_html(self::notice()) . '</p>' : (string) $message;
    }

    /** Divi, RealHomes and Elementor have no filter for their success text, so it is replaced in the response. */
    public static function watchOutput(): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || is_user_logged_in()) {
            return;
        }
        if (in_array(self::context(), ['divi', 'realhomes', 'elementor'], true) || RegistrationHold::isAjaxRegistration()) {
            ob_start([self::class, 'rewriteOutput']);
        }
    }

    public static function rewriteOutput(string $output): string
    {
        if (!self::$held && !RegistrationHold::heldInThisRequest()) {
            return $output;
        }
        $notice = RegistrationHold::heldInThisRequest() ? RegistrationHold::notice() : self::notice();
        $json = json_decode($output, true);
        if (is_array($json)) {
            if (isset($json['message'])) {
                $json['message'] = $notice;
            }
            if (isset($json['data']['message'])) {
                $json['data']['message'] = $notice;
            }

            return (string) wp_json_encode($json);
        }

        return (string) preg_replace('#(<div class="et-pb-contact-message"[^>]*>)\s*<p>.*?</p>#s', '$1<p>' . esc_html($notice) . '</p>', $output);
    }

    public static function notice(): string
    {
        return __('Almost done: we have sent you an email. Your message will not be delivered until you confirm it from that email. If you cannot see it, check your spam folder.', 'draco-insomnis');
    }
}
