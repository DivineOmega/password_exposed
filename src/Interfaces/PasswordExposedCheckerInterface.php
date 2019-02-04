<?php

namespace DivineOmega\PasswordExposed\Interfaces;

/**
 * Interface PasswordExposedCheckerInterface.
 */
interface PasswordExposedCheckerInterface
{
    public const NOT_EXPOSED = 'not_exposed';
    public const EXPOSED = 'exposed';
    public const UNKNOWN = 'unknown';

    /**
     * @param string $password
     *
     * @see PasswordStatus
     *
     * @return string
     */
    public function passwordExposed(string $password): string;

    /**
     * @param $hash
     *
     * @see PasswordStatus
     *
     * @return string
     */
    public function passwordExposedByHash(string $hash): string;

    /**
     * @param string $password
     *
     * @return bool|null
     */
    public function isExposed(string $password): ?bool;

    /**
     * @param string $hash
     *
     * @return bool|null
     */
    public function isExposedByHash(string $hash): ?bool;
}
