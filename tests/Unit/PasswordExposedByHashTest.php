<?php

namespace DivineOmega\PasswordExposed\Tests;

use DivineOmega\PasswordExposed\PasswordExposedChecker;
use DivineOmega\PasswordExposed\PasswordStatus;
use Faker\Factory;
use PHPUnit\Framework\TestCase;

class PasswordExposedByHashTest extends TestCase
{
    /** @var PasswordExposedChecker */
    private $checker;

    protected function setUp()
    {
        $this->checker = new PasswordExposedChecker();
    }

    public function testFunctionExists()
    {
        $this->assertTrue(function_exists('password_exposed_by_hash'));
    }

    /**
     * @return array
     */
    public function exposedPasswordHashProvider()
    {
        return [
            [sha1('test')],
            [sha1('password')],
            [sha1('hunter2')],
        ];
    }

    /**
     * @dataProvider exposedPasswordHashProvider
     *
     * @param string $hash
     */
    public function testExposedPasswords($hash)
    {
        $this->assertEquals($this->checker->passwordExposedByHash($hash), PasswordStatus::EXPOSED);
        $this->assertEquals(password_exposed_by_hash($hash), PasswordStatus::EXPOSED);
    }

    public function testNotExposedPasswords()
    {
        $this->assertEquals(
            $this->checker->passwordExposedByHash($this->getPasswordHashUnlikelyToBeExposed()),
            PasswordStatus::NOT_EXPOSED
        );
        $this->assertEquals(
            password_exposed_by_hash($this->getPasswordHashUnlikelyToBeExposed()),
            PasswordStatus::NOT_EXPOSED
        );
    }

    /**
     * @return string
     */
    private function getPasswordHashUnlikelyToBeExposed()
    {
        $faker = Factory::create();

        return sha1($faker->words(6, true));
    }
}
