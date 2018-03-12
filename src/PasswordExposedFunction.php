<?php

use DivineOmega\PasswordExposed\PasswordExposedChecker;

if (!function_exists('password_exposed')) {
    /**
     * @param string $password
     *
     * @return string
     */
    function password_exposed($password)
    {
        return (new PasswordExposedChecker())->passwordExposed($password);
    }
}
