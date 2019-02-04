<?php

use DivineOmega\PasswordExposed\PasswordExposedChecker;

/**
 * @param string $password
 *
 * @return string
 */
function password_exposed($password): string
{
    return (new PasswordExposedChecker())->passwordExposed($password);
}

/**
 * @param string $hash
 *
 * @return string
 */
function password_exposed_by_hash($hash): string
{
    return (new PasswordExposedChecker())->passwordExposedByHash($hash);
}

/**
 * @param string $password
 *
 * @return bool|null
 */
function password_is_exposed($password): ?bool
{
    return (new PasswordExposedChecker())->isExposed($password);
}

/**
 * @param string $hash
 *
 * @return bool|null
 */
function password_is_exposed_by_hash($hash): ?bool
{
    return (new PasswordExposedChecker())->isExposedByHash($hash);
}
