<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Plugin;

use DracoInsomnis\Core\Shield;
use DracoInsomnis\Magento\Model\MagentoHost;
use DracoInsomnis\Magento\Model\Settings;
use Magento\Customer\Controller\Account\CreatePost;
use Magento\Customer\Model\Session as CustomerSession;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\Controller\Result\RedirectFactory;
use Magento\Framework\Message\ManagerInterface as Messages;

/** The "Create an Account" form: a bot gets no account, a person notices nothing. */
class SignUpShieldPlugin
{
    public function __construct(
        private MagentoHost $host,
        private Settings $settings,
        private CustomerSession $customers,
        private RedirectFactory $redirects,
        private Messages $messages
    ) {
    }

    /** @return mixed */
    public function aroundExecute(CreatePost $subject, callable $proceed)
    {
        $http = $subject->getRequest();
        if (!$this->settings->shield() || !$http instanceof HttpRequest || !$http->isPost() || $this->customers->isLoggedIn()) {
            return $proceed();
        }
        $request = MagentoHost::request($http);
        $shield = new Shield($this->host);
        // No usernames in a shop: the name is where sign-up bots put their random strings.
        $name = (string) preg_replace('/\s+/', '', $request->field('firstname') . $request->field('lastname'));
        $result = $shield->judge($request, 'magento_register', ['username' => $name, 'email' => $request->field('email'), 'role' => ''], null, time());
        if ($result['verdict'] !== 'bot') {
            return $proceed();
        }
        $shield->slowDown();
        $this->messages->addErrorMessage(__('The registration could not be completed.'));

        return $this->redirects->create()->setPath('customer/account/create');
    }
}
