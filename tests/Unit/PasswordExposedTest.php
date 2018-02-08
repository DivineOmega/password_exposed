<?php

use DivineOmega\PasswordExposed\PasswordStatus;
use PHPUnit\Framework\TestCase;

class PasswordExposedTest extends TestCase
{
    public function testFunctionExists()
    {
        $this->assertTrue(function_exists('password_exposed'));
    }

    public function testExposedPasswords()
    {
        $passwords = ['test', 'password', 'hunter2'];

        foreach ($passwords as $password) {
            $this->assertEquals(password_exposed($password), PasswordStatus::EXPOSED);
        }
    }

    public function testNotExposedPasswords()
    {
        $this->assertEquals(password_exposed($this->getPasswordUnlikelyToBeExposed()), PasswordStatus::NOT_EXPOSED);
    }

    private function getPasswordUnlikelyToBeExposed()
    {
        $faker = Faker\Factory::create();

        $password = '';

        for ($i = 0; $i < 6; $i++) {
            $password .= $faker->word();
            $password .= ' ';
        }

        $password = trim($password);

        return $password;
    }
}
