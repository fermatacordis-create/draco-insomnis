<?php

/**
 * @package     Draco Insomnis for Joomla
 * @copyright   (C) 2026 Notorius Vision
 * @license     GNU General Public License version 2 or later
 */

\defined('_JEXEC') or die;

use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;
use Notorius\Plugin\System\DracoInsomnis\Extension\DracoInsomnis;

require_once \dirname(__DIR__) . '/lib/autoload.php';

return new class () implements ServiceProviderInterface {
    public function register(Container $container): void
    {
        $container->set(
            PluginInterface::class,
            function (Container $container) {
                $plugin = new DracoInsomnis((array) PluginHelper::getPlugin('system', 'dracoinsomnis'));
                $plugin->setApplication(Factory::getApplication());

                return $plugin;
            }
        );
    }
};
