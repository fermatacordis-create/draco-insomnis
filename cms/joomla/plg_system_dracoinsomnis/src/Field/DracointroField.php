<?php

/**
 * @package     Draco Insomnis for Joomla
 * @copyright   (C) 2026 Notorius Vision
 * @license     GNU General Public License version 2 or later
 */

namespace Notorius\Plugin\System\DracoInsomnis\Field;

use Joomla\CMS\Form\FormField;
use Joomla\CMS\Language\Text;
use Notorius\Plugin\System\DracoInsomnis\JoomlaHost;

\defined('_JEXEC') or die;

/** What the plugin does, and the visitor address as it sees it. */
final class DracointroField extends FormField
{
    protected $type = 'Dracointro';

    protected function getLabel()
    {
        return '';
    }

    protected function getInput()
    {
        $h = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
        $proxy = (string) ($this->form->getValue('proxy_header', 'params') ?? '');
        $request = JoomlaHost::request();

        return '<div class="alert alert-info"><p><em>Ab insomni custodita dracone.</em> ' . $h(Text::_('PLG_SYSTEM_DRACOINSOMNIS_INTRO')) . '</p>'
            . '<p class="mb-0">' . Text::sprintf('PLG_SYSTEM_DRACOINSOMNIS_YOUR_IP', '<code>' . $h($request->ip($proxy)) . '</code>', '<code>' . $h($request->remote()) . '</code>') . '</p></div>';
    }
}
