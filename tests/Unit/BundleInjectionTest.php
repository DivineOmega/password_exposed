<?php

namespace DivineOmega\PasswordExposed\Tests;

use DivineOmega\DOFileCachePSR6\CacheItemPool;
use DivineOmega\PasswordExposed\PasswordExposedChecker;
use DivineOmega\PasswordExposed\PasswordStatus;
use ParagonIE\Certainty\Bundle;
use PHPUnit\Framework\TestCase;

class BundleInjectionTest extends TestCase
{
    public function testLocalBundleInjection()
    {
        $pemFiles = glob(__DIR__.'/../../vendor/paragonie/certainty/data/*.pem');
        $bundle = new Bundle(end($pemFiles));

        $cache = new CacheItemPool();
        $cache->changeConfig([
            'cacheDirectory' => __DIR__ . '/../../cache/',
            'gzipCompression' => false,
        ]);

        $passwordExposedChecker = new PasswordExposedChecker(null, $cache, $bundle);

        $this->assertEquals(PasswordStatus::EXPOSED, $passwordExposedChecker->passwordExposed('hunter2'));
    }
}
