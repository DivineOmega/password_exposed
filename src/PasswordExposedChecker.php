<?php

namespace DivineOmega\PasswordExposed;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;
use rapidweb\RWFileCachePSR6\CacheItemPool;

class PasswordExposedChecker
{
    private $client;
    private $cache;

    const CACHE_EXPIRY_SECONDS = 60 * 60 * 24 * 30;

    public function __construct()
    {
        $this->client = new Client([
            'base_uri' => 'https://api.pwnedpasswords.com/',
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

        $cacheKey = substr($hash, 0, 2).'_'.substr($hash, 2);

        $cacheItem = $this->cache->getItem($cacheKey);

        if ($cacheItem->isHit()) {
            return $cacheItem->get();
        }

        $status = $this->getPasswordStatus($hash, $this->makeRequest($hash));

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

        return $this->client->request('GET', 'range/'.substr($hash, 0, 5), $options);
    }

    private function getPasswordStatus($hash, Response $response)
    {
        if ($response->getStatusCode() !== 200) {
            return PasswordStatus::UNKNOWN;
        }

        $hash = strtoupper($hash);
        $hashSuffix = substr($hash, 5);

        $body = (string) $response->getBody();

        $lines = explode("\r\n", $body);

        foreach ($lines as $line) {
            list($exposedHashSuffix, $occurrences) = explode(':', $line);
            if ($hashSuffix == $exposedHashSuffix) {
                return PasswordStatus::EXPOSED;
            }
        }

        return PasswordStatus::NOT_EXPOSED;
    }
}
