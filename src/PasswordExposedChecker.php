<?php

namespace DivineOmega\PasswordExposed;

use DivineOmega\DOFileCachePSR6\CacheItemPool;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use ParagonIE\Certainty\Bundle;
use ParagonIE\Certainty\Fetch;
use ParagonIE\Certainty\RemoteFetch;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Message\ResponseInterface;

class PasswordExposedChecker
{
    /** @var Bundle $bundle */
    private $bundle;

    /** @var Client $client */
    private $client;

    /** @var CacheItemPoolInterface $cache */
    private $cache;

    const CACHE_EXPIRY_SECONDS = 60 * 60 * 24 * 30;

    /**
     * PasswordExposedChecker constructor.
     *
     * @param Client|null                 $client
     * @param CacheItemPoolInterface|null $cache
     * @param Bundle|null                 $bundle
     *
     * @throws \ParagonIE\Certainty\Exception\CertaintyException
     * @throws \SodiumException
     */
    public function __construct(Client $client = null, CacheItemPoolInterface $cache = null, Bundle $bundle = null)
    {
        if (!$client) {
            $client = new Client([
                'base_uri' => 'https://api.pwnedpasswords.com/',
                'timeout'  => 3.0,
            ]);
        }
        $this->client = $client;

        if (!$cache) {
            $cache = new CacheItemPool();
            $cache->changeConfig([
                'cacheDirectory' => sys_get_temp_dir().'/password-exposed-cache/',
            ]);
        }
        $this->cache = $cache;

        if (!$bundle) {
            $bundle = $this->getBundleFromCertainty();
        }
        $this->bundle = $bundle;
    }

    /**
     * Get secure bundle from Certainty.
     *
     * @throws \ParagonIE\Certainty\Exception\CertaintyException
     * @throws \SodiumException
     *
     * @return Bundle
     */
    private function getBundleFromCertainty()
    {
        $ourCertaintyDataDir = __DIR__.'/../bundles/';

        if (!is_writable($ourCertaintyDataDir)) {

            // If we can't write to the our Certainty data directory, just
            // use the latest bundle from the Certainty package.
            return (new Fetch($ourCertaintyDataDir))->getLatestBundle();
        } else {
            if (PHP_INT_SIZE === 4 && !extension_loaded('sodium')) {

                // If the platform would run verification checks slowly, use the
                // latest bundle from the Certainty package and disable verification.
                return (new Fetch($ourCertaintyDataDir))->getLatestBundle(false, false);
            } else {

                // If the platform can run verification checks well enough, get
                // latest remote bundle and verify it.
                return (new RemoteFetch($ourCertaintyDataDir))->getLatestBundle();
            }
        }
    }

    /**
     * Check if password has been exposed.
     *
     * @param string $password
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Psr\Cache\InvalidArgumentException
     *
     * @return string (see PasswordStatus)
     */
    public function passwordExposed($password)
    {
        return $this->passwordExposedByHash(sha1($password));
    }

    /**
     * Check if password has been exposed (using SHA1 hash).
     *
     * @param string $hash Hexadecimal SHA-1 hash of the password
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Psr\Cache\InvalidArgumentException
     *
     * @return string (see PasswordStatus)
     */
    public function passwordExposedByHash($hash)
    {
        $cacheKey = substr($hash, 0, 2).'_'.substr($hash, 2, 3);

        $cacheItem = $this->cache->getItem($cacheKey);

        if ($cacheItem->isHit()) {
            /** @var string $responseBody */
            $responseBody = $cacheItem->get();
        } else {
            try {
                /** @var ResponseInterface $response */
                $response = $this->makeRequest($hash);
            } catch (ConnectException $e) {
                return PasswordStatus::UNKNOWN;
            }

            if ($response->getStatusCode() !== 200) {
                return PasswordStatus::UNKNOWN;
            }

            /** @var string $responseBody */
            $responseBody = (string) $response->getBody();

            $cacheItem->set($responseBody);
            $cacheItem->expiresAfter(self::CACHE_EXPIRY_SECONDS);
            $this->cache->save($cacheItem);
        }

        return $this->getPasswordStatus($hash, $responseBody);
    }

    /**
     * Perform request to HIBP Passwords API.
     *
     * @param string $hash
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    private function makeRequest($hash)
    {
        $options = [
            'exceptions' => false,
            'headers'    => [
                'User_Agent' => 'password_exposed - https://github.com/DivineOmega/password_exposed',
            ],
            'verify' => ($this->bundle->getFilePath()),
        ];

        return $this->client->request('GET', 'range/'.substr($hash, 0, 5), $options);
    }

    /**
     * Convert response body to PasswordStatus constant.
     *
     * @param string $hash
     * @param string $responseBody
     *
     * @return string (see PasswordStatus)
     */
    private function getPasswordStatus($hash, $responseBody)
    {
        $hash = strtoupper($hash);
        $hashSuffix = substr($hash, 5);

        $lines = explode("\r\n", $responseBody);

        foreach ($lines as $line) {
            list($exposedHashSuffix, $occurrences) = explode(':', $line);
            if (hash_equals($hashSuffix, $exposedHashSuffix)) {
                return PasswordStatus::EXPOSED;
            }
        }

        return PasswordStatus::NOT_EXPOSED;
    }
}
