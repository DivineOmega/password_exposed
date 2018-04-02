<?php

use DivineOmega\PasswordExposed\PasswordStatus;
use PHPUnit\Framework\TestCase;
use DivineOmega\PasswordExposed\PasswordExposedChecker;
use ParagonIE\Certainty\Bundle;

class BundleInjectionTest extends TestCase
{
    public function testLocalBundleInjection()
    {
        $pemFiles = glob(__DIR__.'/../../vendor/paragonie/certainty/data/*.pem');
        $bundle = new Bundle(end($pemFiles));
        
        $passwordExposedChecker = new PasswordExposedChecker(null, null, $bundle);

        $this->assertEquals(PasswordStatus::EXPOSED, $passwordExposedChecker->passwordExposed('hunter2'));
    }
}
