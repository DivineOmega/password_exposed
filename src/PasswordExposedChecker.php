<?php

namespace DivineOmega\PasswordExposed;

use DivineOmega\DOFileCachePSR6\CacheItemPool;
use Http\Adapter\Guzzle6\Client as GuzzleAdapter;
use Http\Discovery\Psr17FactoryDiscovery;
use ParagonIE\Certainty\Bundle;
use ParagonIE\Certainty\Fetch;
use ParagonIE\Certainty\RemoteFetch;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriFactoryInterface;

class PasswordExposedChecker
{
    /** @var Bundle */
    protected $bundle;

    /** @var ClientInterface */
    protected $client;

    /** @var CacheItemPoolInterface */
    protected $cache;

    /** @var RequestFactoryInterface */
    protected $requestFactory;

    /** @var UriFactoryInterface */
    protected $uriFactory;

    const CACHE_EXPIRY_SECONDS = 60 * 60 * 24 * 30;

    /**
     * @param ClientInterface|null         $client
     * @param CacheItemPoolInterface|null  $cache
     * @param Bundle|null                  $bundle
     * @param RequestFactoryInterface|null $requestFactory
     * @param UriFactoryInterface|null     $uriFactory
     */
    public function __construct(
        ClientInterface $client = null,
        CacheItemPoolInterface $cache = null,
        Bundle $bundle = null,
        RequestFactoryInterface $requestFactory = null,
        UriFactoryInterface $uriFactory = null
    )
    {
        $this->bundle = $bundle ?: $this->createBundle();
        $this->client = $client ?: $this->createClient();
        $this->cache = $cache ?: $this->createCache();
        $this->requestFactory = $requestFactory ?: Psr17FactoryDiscovery::findRequestFactory();
        $this->uriFactory = $uriFactory ?: Psr17FactoryDiscovery::findUrlFactory();
    }

    /**
     * @return Bundle
     */
    protected function createBundle()
    {
        return $this->getBundleFromCertainty();
    }

    /**
     * @return ClientInterface
     */
    protected function createClient()
    {
        return GuzzleAdapter::createWithConfig([
            'timeout'    => 3.0,
            'exceptions' => false,
            'headers'    => [
                'User_Agent' => 'password_exposed - https://github.com/DivineOmega/password_exposed',
            ],
            'verify'     => ($this->bundle->getFilePath()),
        ]);
    }

    /**
     * @return CacheItemPool
     */
    protected function createCache()
    {
        $cache = new CacheItemPool();
        $cache->changeConfig([
            'cacheDirectory' => sys_get_temp_dir() . '/password-exposed-cache/',
        ]);

        return $cache;
    }

    /**
     * @return Bundle
     */
    private function getBundleFromCertainty()
    {
        $ourCertaintyDataDir = __DIR__ . '/../bundles/';

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
     * @param string $password
     *
     * @return string (see PasswordStatus)
     */
    public function passwordExposed($password)
    {
        return $this->passwordExposedByHash(sha1($password));
    }

    /**
     * @param string $hash Hexadecimal SHA-1 hash of the password
     *
     * @return string (see PasswordStatus)
     */
    public function passwordExposedByHash($hash)
    {
        $cacheKey = substr($hash, 0, 2) . '_' . substr($hash, 2, 3);

        $cacheItem = $this->cache->getItem($cacheKey);

        if ($cacheItem->isHit()) {
            /** @var string $responseBody */
            $responseBody = $cacheItem->get();
        } else {
            try {
                /** @var ResponseInterface $response */
                $response = $this->makeRequest($hash);
            } catch (NetworkExceptionInterface $e) {
                return PasswordStatus::UNKNOWN;
            }

            if ($response->getStatusCode() !== 200) {
                return PasswordStatus::UNKNOWN;
            }

            /** @var string $responseBody */
            $responseBody = $response->getBody()->getContents();
        }

        $cacheItem->set($responseBody);
        $cacheItem->expiresAfter(self::CACHE_EXPIRY_SECONDS);
        $this->cache->save($cacheItem);

        return $this->getPasswordStatus($hash, $responseBody);
    }

    /**
     * @param string $hash
     *
     * @return ResponseInterface
     */
    private function makeRequest($hash)
    {
        $uri = $this->uriFactory->createUri('https://api.pwnedpasswords.com/range/' . substr($hash, 0, 5));
        $request = $this->requestFactory->createRequest('GET', $uri);

        return $this->client->sendRequest($request);
    }

    /**
     * @param string $hash
     * @param string $responseBody
     *
     * @return string
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
