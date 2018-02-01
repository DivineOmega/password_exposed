<?php

use PHPUnit\Framework\TestCase;
use Faker\Factory;

class PasswordExposedTest extends TestCase
{
    public function testExposedPasswords()
    {
        $passwords = ['test', 'password', 'hunter2'];

        foreach($passwords as $password) {
            $this->assertTrue(password_exposed('test'));
        }
    }

    public function testNotExposedPasswords()
    {
        $this->assertFalse(password_exposed($this->getPasswordUnlikelyToBeExposed()));
    }

    private function getPasswordUnlikelyToBeExposed()
    {
        $faker = Faker\Factory::create();

        $password = '';

        for ($i=0; $i < 6; $i++) { 
            $password .= $faker->word();
            $password .= ' ';
        }

        $password = trim($password);

        return $password;
    }

}