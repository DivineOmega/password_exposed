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

/**
 * @param string $hash
 *
 * @return string
 */
function password_exposed_by_hash($hash)
{
    return (new PasswordExposedChecker())->passwordExposedByHash($hash);
}
