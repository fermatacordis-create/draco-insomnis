<?php
/**
 * Draco Insomnis 0.1.15: the password rules need a hook that runs before the customer pages handle
 * their forms.
 */
if (!defined('_PS_VERSION_')) {
    exit;
}

function upgrade_module_0_1_15($module)
{
    return $module->registerHook('actionFrontControllerSetMedia');
}
