<?php

namespace DivineOmega\PasswordExposed\Tests;

use DivineOmega\DOFileCachePSR6\CacheItemPool;
use DivineOmega\PasswordExposed\Enums\PasswordStatus;
use DivineOmega\PasswordExposed\PasswordExposedChecker;
use Faker\Factory;
use PHPUnit\Framework\TestCase;

class PasswordExposedByHashTest extends TestCase
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
        $this->assertEquals($this->checker->isExposedByHash($hash), true);
        $this->assertEquals(password_is_exposed_by_hash($hash), true);
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
        $this->assertEquals(
            $this->checker->isExposedByHash($this->getPasswordHashUnlikelyToBeExposed()),
            false
        );
        $this->assertEquals(
            password_is_exposed_by_hash($this->getPasswordHashUnlikelyToBeExposed()),
            false
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
