<?php

use DivineOmega\PasswordExposed\PasswordExposedChecker;

if (!function_exists('password_exposed')) {
    
    function password_exposed($password)
    {
        return (new PasswordExposedChecker)->passwordExposed($password);
    }
}