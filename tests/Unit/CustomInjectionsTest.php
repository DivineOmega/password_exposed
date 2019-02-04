<?php

namespace DivineOmega\PasswordExposed\Tests;

use Buzz\Client\FileGetContents;
use DivineOmega\DOFileCachePSR6\CacheItemPool;
use DivineOmega\PasswordExposed\Enums\PasswordStatus;
use DivineOmega\PasswordExposed\PasswordExposedChecker;
use Faker\Factory;
use Http\Discovery\Psr17FactoryDiscovery;
use ParagonIE\Certainty\Bundle;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Adapter\NullAdapter;

class CustomInjectionsTest extends TestCase
{
    public function testConnection()
    {
        $cache = new NullAdapter();

        $passwordExposedChecker = new PasswordExposedChecker(null, $cache);

        $this->assertEquals(true, $passwordExposedChecker->isExposed('hunter2'));
        $this->assertEquals(false, $passwordExposedChecker->isExposed($this->getPasswordHashUnlikelyToBeExposed()));
    }

    public function testCustomLibrary()
    {
        $client = new FileGetContents(Psr17FactoryDiscovery::findResponseFactory());
        $cache = new FilesystemAdapter('test', 3600, __DIR__.'/../../cache/symfony');

        $passwordExposedChecker = new PasswordExposedChecker($client, $cache);

        $this->assertEquals(PasswordStatus::EXPOSED, $passwordExposedChecker->passwordExposed('hunter2'));
        $this->assertEquals(PasswordStatus::NOT_EXPOSED, $passwordExposedChecker->passwordExposed($this->getPasswordHashUnlikelyToBeExposed()));
    }

    public function testLocalBundleInjection()
    {
        $pemFiles = glob(__DIR__.'/../../vendor/paragonie/certainty/data/*.pem');
        $bundle = new Bundle(end($pemFiles));

        $cache = new CacheItemPool();
        $cache->changeConfig(
            [
                'cacheDirectory'  => __DIR__.'/../../cache/dofilecache/',
                'gzipCompression' => false,
            ]
        );

        $passwordExposedChecker = new PasswordExposedChecker(null, $cache);
        $passwordExposedChecker->setBundle($bundle);

        $this->assertEquals(PasswordStatus::EXPOSED, $passwordExposedChecker->passwordExposed('hunter2'));
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
