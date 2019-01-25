<?php

namespace DivineOmega\PasswordExposed\Tests;

use DivineOmega\PasswordExposed\PasswordExposedChecker;
use DivineOmega\PasswordExposed\PasswordStatus;
use Faker\Factory;
use PHPUnit\Framework\TestCase;

class PasswordExposedTest extends TestCase
{
    /** @var PasswordExposedChecker */
    private $checker;

    protected function setUp()
    {
        $this->checker = new PasswordExposedChecker();
    }

    public function testFunctionExists()
    {
        $this->assertTrue(function_exists('password_exposed'));
    }

    public function exposedPasswordsProvider()
    {
        return [
            ['test'],
            ['password'],
            ['hunter2'],
        ];
    }

    /**
     * @dataProvider exposedPasswordsProvider
     */
    public function testExposedPasswords($password)
    {
        $this->assertEquals($this->checker->passwordExposed($password), PasswordStatus::EXPOSED);
        $this->assertEquals(password_exposed($password), PasswordStatus::EXPOSED);
        $this->assertEquals($this->checker->isExposed($password), true);
    }

    public function testNotExposedPasswords()
    {
        $this->assertEquals(
            $this->checker->passwordExposed($this->getPasswordUnlikelyToBeExposed()),
            PasswordStatus::NOT_EXPOSED
        );
        $this->assertEquals(password_exposed($this->getPasswordUnlikelyToBeExposed()), PasswordStatus::NOT_EXPOSED);
        $this->assertEquals(
            $this->checker->isExposed($this->getPasswordUnlikelyToBeExposed()),
            false
        );
    }

    private function getPasswordUnlikelyToBeExposed()
    {
        $faker = Factory::create();

        $password = '';

        for ($i = 0; $i < 6; $i++) {
            $password .= $faker->word();
            $password .= ' ';
        }

        $password = trim($password);

        return $password;
    }
}
