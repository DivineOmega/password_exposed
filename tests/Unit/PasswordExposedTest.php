<?php

namespace DivineOmega\PasswordExposed\Tests;

use DivineOmega\DOFileCachePSR6\CacheItemPool;
use DivineOmega\PasswordExposed\Enums\PasswordStatus;
use DivineOmega\PasswordExposed\PasswordExposedChecker;
use Faker\Factory;
use PHPUnit\Framework\TestCase;

class PasswordExposedTest extends TestCase
{
    /** @var PasswordExposedChecker */
    private $checker;

    protected function setUp()
    {
        $cache = new CacheItemPool();
        $cache->changeConfig(
            [
                'cacheDirectory'  => __DIR__.'/../../cache/dofilecache/',
                'gzipCompression' => false,
            ]
        );
        $this->checker = new PasswordExposedChecker(null, $cache);
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
        $this->assertEquals(password_is_exposed($password), true);
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
        $this->assertEquals(
            password_is_exposed($this->getPasswordUnlikelyToBeExposed()),
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
