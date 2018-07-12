<?php

use DivineOmega\PasswordExposed\PasswordExposedChecker;

/**
 * @param string $password
 *
 * @return string
 */
function password_exposed($password)
{
    return (new PasswordExposedChecker())->passwordExposed($password);
}
