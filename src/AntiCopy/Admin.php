<?php

declare(strict_types=1);

namespace DracoInsomnis\AntiCopy;

use DracoInsomnis\Admin\Brand;
use DracoInsomnis\Input;
use DracoInsomnis\Shield\Store;

defined('ABSPATH') || exit;

/** The owner's screen for the anti-copy module. */
final class Admin
{
    public const SLUG = 'draco-insomnis-anticopy';
    private const ACTION = 'draco_anticopy_admin';

    public static function register(): void
    {
        add_action('admin_menu', [self::class, 'menu'], 13);
        add_action('admin_post_' . self::ACTION, [self::class, 'save']);
    }

    public static function menu(): void
    {
        $title = __('Anti-copy', 'draco-insomnis');
        add_submenu_page(Brand::PARENT, $title, $title, 'manage_options', self::SLUG, [self::class, 'render']);
    }

    public static function save(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do this.', 'draco-insomnis'), 403);
        }
        check_admin_referer(self::ACTION);
        foreach ([Guard::OPTION_REST => 'rest', Guard::OPTION_RATE => 'rate'] as $option => $field) {
            $mode = Input::post($field);
            update_option($option, in_array($mode, Guard::MODES, true) ? $mode : 'off');
        }
        $allow = isset($_POST['allow']) && is_string($_POST['allow']) ? sanitize_textarea_field(wp_unslash($_POST['allow'])) : '';
        update_option(Guard::OPTION_REST_ALLOW, $allow, false);
        update_option(Guard::OPTION_RATE_IP, max(10, Input::postInt('rate_ip', Guard::DEFAULT_RATE_IP)));
        update_option(Guard::OPTION_RATE_NET, max(10, Input::postInt('rate_net', Guard::DEFAULT_RATE_NET)));
        wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&result=ok'));
        exit;
    }

    public static function render(): void
    {
        echo '<div class="wrap">';
        Brand::header(__('Anti-copy', 'draco-insomnis'));
        echo '<p>' . esc_html__('Makes it harder to copy the whole site in one go, without getting in the way of visitors or search engines. People logged in and the addresses an administrator used are never limited. Start with "Log only" for a few days and look at the list below.', 'draco-insomnis') . '</p>';
        if (Input::get('result') === 'ok') {
            echo '<div class="notice notice-success"><p>' . esc_html__('Changes saved.', 'draco-insomnis') . '</p></div>';
        }
        $modes = [
            'off' => __('Off', 'draco-insomnis'),
            'log' => __('Log only: write down what it would stop, without stopping anything', 'draco-insomnis'),
            'block' => __('Block', 'draco-insomnis'),
        ];
        $radios = static function (string $name, string $current) use ($modes): void {
            foreach ($modes as $value => $label) {
                echo '<label style="display:block;margin:4px 0"><input type="radio" name="' . esc_attr($name) . '" value="' . esc_attr($value) . '" ' . checked($current, $value, false) . '> ' . esc_html($label) . '</label>';
            }
        };
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '">';

        echo '<h2>' . esc_html__('Content API', 'draco-insomnis') . '</h2>';
        echo '<p>' . esc_html__('WordPress publishes every post, page and image as JSON at /wp-json/wp/v2/, which lets anyone download the whole site in a few requests. This closes those reads to anonymous visitors; the pages themselves stay public.', 'draco-insomnis') . '</p>';
        $radios('rest', Guard::mode(Guard::OPTION_REST));
        echo '<p><label for="draco_allow"><strong>' . esc_html__('Routes that stay open', 'draco-insomnis') . '</strong></label><br>';
        echo '<textarea id="draco_allow" name="allow" rows="4" cols="60" class="code" placeholder="/wp/v2/posts">' . esc_textarea((string) get_option(Guard::OPTION_REST_ALLOW, '')) . '</textarea><br>';
        echo '<span class="description">' . esc_html__('One per line, for example /wp/v2/posts if your theme loads more posts with JavaScript. The log below shows which routes visitors really use. Other APIs (forms, shop, embeds) are never affected.', 'draco-insomnis') . '</span></p>';

        echo '<h2>' . esc_html__('Pace', 'draco-insomnis') . '</h2>';
        echo '<p>' . esc_html__('More pages per minute than a person reads get "429 Too many requests" for the rest of that minute. Google, Bing, Apple and Yandex are recognised by their reverse DNS and never limited; a program that only pretends to be them is.', 'draco-insomnis') . '</p>';
        $radios('rate', Guard::mode(Guard::OPTION_RATE));
        $ip = (int) get_option(Guard::OPTION_RATE_IP, Guard::DEFAULT_RATE_IP);
        $net = (int) get_option(Guard::OPTION_RATE_NET, Guard::DEFAULT_RATE_NET);
        echo '<p><label>' . esc_html__('Pages per minute from one address', 'draco-insomnis') . ' <input type="number" min="10" name="rate_ip" value="' . esc_attr((string) $ip) . '" class="small-text"></label></p>';
        echo '<p><label>' . esc_html__('Pages per minute from one network (the 256 addresses around it)', 'draco-insomnis') . ' <input type="number" min="10" name="rate_net" value="' . esc_attr((string) $net) . '" class="small-text"></label></p>';
        echo '<p class="description">' . esc_html__('Only requests that reach WordPress count: images, styles and pages served by a cache do not. Each counted request writes two small counters, so on a very busy site without an object cache keep this off or in log mode.', 'draco-insomnis') . '</p>';
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</form>';

        $what = [
            'anticopy_rest' => __('content API', 'draco-insomnis'),
            'anticopy_rate_ip' => __('too fast, one address', 'draco-insomnis'),
            'anticopy_rate_net' => __('too fast, one network', 'draco-insomnis'),
        ];
        echo '<h2>' . esc_html__('Recent', 'draco-insomnis') . '</h2>';
        echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Date (UTC)', 'draco-insomnis') . '</th><th>IP</th><th>' . esc_html__('What', 'draco-insomnis') . '</th><th>' . esc_html__('Address requested', 'draco-insomnis') . '</th><th>' . esc_html__('Browser', 'draco-insomnis') . '</th><th>' . esc_html__('Result', 'draco-insomnis') . '</th></tr></thead><tbody>';
        $rows = Store::recentWhere('anticopy:');
        foreach ($rows as $r) {
            $reason = (string) $r['reasons'];
            $blocked = str_ends_with($reason, '_block');
            $key = (string) preg_replace('/_(block|log)$/', '', $reason);
            $fields = json_decode((string) $r['fields'], true);
            echo '<tr><td>' . esc_html((string) $r['created_at']) . '</td><td>' . esc_html((string) $r['ip']) . '</td><td>' . esc_html($what[$key] ?? $key) . '</td><td><code>'
                . esc_html((string) (is_array($fields) ? ($fields['referer'] ?? '') : '')) . '</code></td><td>' . esc_html(substr((string) $r['user_agent'], 0, 60)) . '</td><td>'
                . esc_html($blocked ? __('Blocked', 'draco-insomnis') : __('Would block', 'draco-insomnis')) . '</td></tr>';
        }
        if ($rows === []) {
            echo '<tr><td colspan="6">' . esc_html__('Nothing recorded yet.', 'draco-insomnis') . '</td></tr>';
        }
        echo '</tbody></table></div>';
    }
}
