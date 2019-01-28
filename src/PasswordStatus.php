<?php

namespace DivineOmega\PasswordExposed;

/**
 * Class PasswordStatus
 *
 * @package DivineOmega\PasswordExposed
 */
abstract class PasswordStatus
{
    public const NOT_EXPOSED = PasswordExposedCheckerInterface::NOT_EXPOSED;
    public const EXPOSED = PasswordExposedCheckerInterface::EXPOSED;
    public const UNKNOWN = PasswordExposedCheckerInterface::UNKNOWN;
}
