<?php

namespace DivineOmega\PasswordExposed;

use GuzzleHttp\Client;
use rapidweb\RWFileCachePSR6\CacheItemPool;

class PasswordExposedChecker
{
    private $client;
    private $cache;

    const CACHE_EXPIRY_SECONDS = 60 * 60 * 24 * 30;

    public function __construct()
    {
        $this->client = new Client([
            'base_uri' => 'https://haveibeenpwned.com/api/v2/',
            'timeout'  => 3.0,
        ]);

        $this->cache = new CacheItemPool();
        $this->cache->changeConfig([
            'cacheDirectory' => '/tmp/password-exposed-cache/',
        ]);
    }

    public function passwordExposed($password)
    {
        $hash = sha1($password);
        unset($password);

        $cacheKey = 'pw_exposed_'.$hash;

        $cacheItem = $this->cache->getItem($cacheKey);

        if ($cacheItem->isHit()) {
            return $cacheItem->get();
        }

        sleep(2);

        $response = $this->makeRequest($hash);

        $status = PasswordStatus::UNKNOWN;

        switch ($response->getStatusCode()) {
            case 200:
                $status = PasswordStatus::EXPOSED;
                break;

            case 404:
                $status = PasswordStatus::NOT_EXPOSED;
                break;
        }

        if (in_array($status, [PasswordStatus::EXPOSED, PasswordStatus::NOT_EXPOSED])) {
            $cacheItem->set($status);
            $cacheItem->expiresAfter(self::CACHE_EXPIRY_SECONDS);
            $this->cache->save($cacheItem);
        }

        return $status;
    }

    private function makeRequest($hash)
    {
        $options = [
            'exceptions' => false,
            'headers'    => [
                'User_Agent' => 'password_exposed - https://github.com/DivineOmega/password_exposed',
            ],
        ];

        return $this->client->request('GET', 'pwnedpassword/'.$hash, $options);
    }
}
