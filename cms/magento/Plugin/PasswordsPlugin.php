<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Plugin;

use DracoInsomnis\Core\Passwords;
use DracoInsomnis\Magento\Model\MagentoHost;
use Magento\Customer\Api\AccountManagementInterface;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Framework\Exception\InputException;
use Magento\Framework\Phrase;

/**
 * Draco's password rules (minimum length, known data breaches) on top of Magento's own, wherever a
 * customer chooses a password: sign-up, account page, reset link, REST and GraphQL. Existing
 * passwords keep working.
 */
class PasswordsPlugin
{
    public function __construct(private MagentoHost $host)
    {
    }

    /** @return array<int, mixed>|null */
    public function beforeCreateAccount(AccountManagementInterface $subject, CustomerInterface $customer, $password = null, $redirectUrl = ''): ?array
    {
        if (is_string($password) && $password !== '') {
            $this->check($password);
        }

        return null;
    }

    /** @return array<int, mixed>|null */
    public function beforeChangePassword(AccountManagementInterface $subject, $email, $currentPassword, $newPassword): ?array
    {
        $this->check((string) $newPassword);

        return null;
    }

    /** @return array<int, mixed>|null */
    public function beforeChangePasswordById(AccountManagementInterface $subject, $customerId, $currentPassword, $newPassword): ?array
    {
        $this->check((string) $newPassword);

        return null;
    }

    /** @return array<int, mixed>|null */
    public function beforeResetPassword(AccountManagementInterface $subject, $email, $resetToken, $newPassword): ?array
    {
        $this->check((string) $newPassword);

        return null;
    }

    private function check(string $password): void
    {
        if (!Passwords::enabled($this->host)) {
            return;
        }
        $problem = Passwords::problem($this->host, $password);
        if ($problem !== '') {
            // Already in the shop's language (MagentoHost::text).
            throw new InputException(new Phrase($problem));
        }
    }
}
