<?php

namespace DivineOmega\PasswordExposed;

use GuzzleHttp\Client;
use rapidweb\RWFileCachePSR6\CacheItemPool;
use GuzzleHttp\Psr7\Response;

class PasswordExposedChecker
{
    private $client;
    private $cache;

    const CACHE_EXPIRY_SECONDS = 60 * 60 * 24 * 30;
    const TIME_BETWEEN_REQUESTS_SECONDS = 2;
    const WAIT_TIMEOUT_SECONDS = 60;

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

        $proceed = $this->wait();

        if (!$proceed) {
            return PasswordStatus::UNKNOWN;
        }

        $status = $this->getPasswordStatus($this->makeRequest($hash));

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

    private function getPasswordStatus(Response $response)
    {
        switch ($response->getStatusCode()) {
            case 200:
                return PasswordStatus::EXPOSED;

            case 404:
                return PasswordStatus::NOT_EXPOSED;
        }

        return PasswordStatus::UNKNOWN;
    }

    /**
     * The wait method waits until 2 seconds have passed since the last request, then returns true.
     * If we have been waiting for greater than self::WAIT_TIMEOUT_SECONDS, give up and return false.
     */
    private function wait()
    {
        $startTime = time();

        while(true) {

            $lastRequestCacheItem = $this->cache->getItem('last_request');
            if (!$lastRequestCacheItem->isHit() || $lastRequestCacheItem->get() < time() - self::TIME_BETWEEN_REQUESTS_SECONDS) {
                $lastRequestCacheItem->set(time());
                $this->cache->save($lastRequestCacheItem);
                return true;
            }
            
            if ($startTime < time() - self::WAIT_TIMEOUT_SECONDS) {
                return false;
            }
            
            sleep(1);

        }
    }
}
