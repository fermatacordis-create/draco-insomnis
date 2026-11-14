<?php
/**
 * Draco Insomnis for PrestaShop. Ab insomni custodita dracone.
 *
 * Anti-bot shield for customer sign-ups (no captcha), application firewall and anti-copy pace limit.
 * The deciding code is the same as in the WordPress plugin (src/Core); this module only connects it
 * to the shop.
 *
 * @author    Notorius Vision
 * @license   GPL-2.0-or-later
 */

declare(strict_types=1);

if (!defined('_PS_VERSION_')) {
    exit;
}

require_once __DIR__ . '/autoload.php';

use DracoInsomnis\Presta\Admin;
use DracoInsomnis\Presta\Front;
use DracoInsomnis\Presta\Settings;
use DracoInsomnis\Presta\Store;

class DracoInsomnis extends Module
{
    public function __construct()
    {
        $this->name = 'dracoinsomnis';
        $this->tab = 'administration';
        $this->version = '0.1.15';
        $this->author = 'Notorius Vision';
        $this->need_instance = 0;
        $this->ps_versions_compliancy = ['min' => '8.0.0', 'max' => _PS_VERSION_];
        $this->bootstrap = true;

        parent::__construct();

        $this->displayName = $this->trans('Draco Insomnis', [], 'Modules.Dracoinsomnis.Admin');
        $this->description = $this->trans('Stops fake customer sign-ups without captchas, firewall and anti-copy limits. Open source.', [], 'Modules.Dracoinsomnis.Admin');
    }

    public function isUsingNewTranslationSystem(): bool
    {
        return true;
    }

    public function install(): bool
    {
        return parent::install()
            && Store::install()
            && Settings::install()
            && $this->registerHook([
                'actionDispatcherBefore',
                'displayCustomerAccountForm',
                'actionSubmitAccountBefore',
                'displayBackOfficeHeader',
                'actionFrontControllerSetMedia',
            ]);
    }

    public function uninstall(): bool
    {
        $ok = parent::uninstall();
        Store::uninstall();
        Settings::uninstall();

        return $ok;
    }

    /** First point of every shop request: firewall and pace limit. */
    public function hookActionDispatcherBefore(array $params): void
    {
        $type = (int) ($params['controller_type'] ?? 0);
        if ($type === Dispatcher::FC_FRONT || $type === Dispatcher::FC_MODULE) {
            Front::request($this);
        }
    }

    /** Inside the sign-up form (account page and checkout): the page stamp and the trap field. */
    public function hookDisplayCustomerAccountForm(array $params): string
    {
        return Front::formFields($this->context);
    }

    /** Before the account exists. False stops the sign-up. */
    public function hookActionSubmitAccountBefore(array $params): bool
    {
        return Front::judgeSignUp($this) && Front::signUpPassword();
    }

    /** Runs before the page handles its form: the password rules on "Your personal information" and the reset link. */
    public function hookActionFrontControllerSetMedia(array $params): void
    {
        Front::passwordChange($this->context);
    }

    /** Remembers the addresses employees work from: never blocked, never limited. */
    public function hookDisplayBackOfficeHeader(array $params): string
    {
        Settings::rememberAdminIp($this->context);

        return '';
    }

    public function getContent(): string
    {
        return (new Admin($this))->render();
    }

    /** For the classes in src/Presta, which cannot call the protected trans(). */
    public function t(string $text): string
    {
        return $this->trans($text, [], 'Modules.Dracoinsomnis.Admin');
    }
}
