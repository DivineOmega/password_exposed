<?php

namespace DivineOmega\PasswordExposed;

use DivineOmega\DOFileCachePSR6\CacheItemPool;
use Http\Adapter\Guzzle6\Client as GuzzleAdapter;
use Http\Discovery\Psr17FactoryDiscovery;
use ParagonIE\Certainty\Bundle;
use ParagonIE\Certainty\Fetch;
use ParagonIE\Certainty\RemoteFetch;
use Psr\Cache\CacheException;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriFactoryInterface;

/**
 * Class PasswordExposedChecker
 *
 * @package DivineOmega\PasswordExposed
 */
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

    protected const CACHE_EXPIRY_SECONDS = 2592000;

    /**
     * @param ClientInterface|null         $client
     * @param CacheItemPoolInterface|null  $cache
     * @param Bundle|null                  $bundle
     * @param RequestFactoryInterface|null $requestFactory
     * @param UriFactoryInterface|null     $uriFactory
     */
    public function __construct(
        ?ClientInterface $client = null,
        ?CacheItemPoolInterface $cache = null,
        ?Bundle $bundle = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?UriFactoryInterface $uriFactory = null
    )
    {
        $this->client = $client;
        $this->cache = $cache;
        $this->bundle = $bundle;
        $this->requestFactory = $requestFactory ?: Psr17FactoryDiscovery::findRequestFactory();
        $this->uriFactory = $uriFactory ?: Psr17FactoryDiscovery::findUrlFactory();
    }

    /**
     * @return Bundle
     */
    protected function createBundle(): ?Bundle
    {
        try {
            return $this->getBundleFromCertainty();
        } catch (\Exception $exception) {
            return null;
        }
    }

    /**
     * @return Bundle
     */
    protected function getBundle(): ?Bundle
    {
        if ($this->bundle === null) {
            $this->bundle = $this->createBundle();
        }

        return $this->bundle;
    }

    /**
     * @return ClientInterface
     */
    protected function createClient(): ClientInterface
    {
        $options = [
            'timeout' => 3,
            'headers' => [
                'User_Agent' => 'password_exposed - https://github.com/DivineOmega/password_exposed',
            ],
        ];

        $bundle = $this->getBundle();
        if ($bundle !== null) {
            $options['verify'] = $bundle->getFilePath();
        }

        return GuzzleAdapter::createWithConfig($options);
    }

    /**
     * @return ClientInterface
     */
    protected function getClient(): ClientInterface
    {
        if ($this->client === null) {
            $this->client = $this->createClient();
        }

        return $this->client;
    }

    /**
     * @return CacheItemPool
     */
    protected function createCache(): CacheItemPoolInterface
    {
        $cache = new CacheItemPool();
        $cache->changeConfig([
            'cacheDirectory' => sys_get_temp_dir() . '/password-exposed-cache/',
        ]);

        return $cache;
    }

    /**
     * @return CacheItemPoolInterface
     */
    protected function getCache(): CacheItemPoolInterface
    {
        if ($this->cache === null) {
            $this->cache = $this->createCache();
        }

        return $this->cache;
    }

    /**
     * @return Bundle
     * @throws \ParagonIE\Certainty\Exception\CertaintyException
     * @throws \SodiumException
     */
    private function getBundleFromCertainty(): Bundle
    {
        $ourCertaintyDataDir = __DIR__ . '/../bundles';

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
     * @see PasswordStatus
     * @return string
     */
    public function passwordExposed($password): string
    {
        return $this->passwordExposedByHash($this->getHash($password));
    }

    /**
     * @param $hash
     *
     * @see PasswordStatus
     * @return string
     */
    public function passwordExposedByHash($hash): string
    {
        $cacheKey = substr($hash, 0, 2) . '_' . substr($hash, 2, 3);

        try {
            $cacheItem = $this->getCache()->getItem($cacheKey);
        } catch (CacheException $e) {
            $cacheItem = null;
        }

        if ($cacheItem !== null && $cacheItem->isHit()) {
            /** @var string $responseBody */
            $responseBody = $cacheItem->get();
        } else {
            try {
                /** @var ResponseInterface $response */
                $response = $this->makeRequest($hash);
            } catch (ClientExceptionInterface $e) {
                return PasswordStatus::UNKNOWN;
            }

            if ($response->getStatusCode() !== 200) {
                return PasswordStatus::UNKNOWN;
            }

            /** @var string $responseBody */
            $responseBody = $response->getBody()->getContents();
        }

        if ($cacheItem !== null) {
            $cacheItem->set($responseBody);
            $cacheItem->expiresAfter(self::CACHE_EXPIRY_SECONDS);
            $this->getCache()->save($cacheItem);
        }

        return $this->getPasswordStatus($hash, $responseBody);
    }

    /**
     * @param string $password
     *
     * @return bool|null
     */
    public function isExposed(string $password): ?bool
    {
        return $this->isExposedByHash($this->getHash($password));
    }

    /**
     * @param string $hash
     *
     * @return bool|null
     */
    public function isExposedByHash(string $hash): ?bool
    {
        $status = $this->passwordExposedByHash($hash);

        switch ($status) {
            case PasswordStatus::EXPOSED:
                return true;
                break;
            case PasswordStatus::NOT_EXPOSED:
                return false;
                break;
            case PasswordStatus::UNKNOWN:
                return null;
                break;
        }
    }

    /**
     * @param $hash
     *
     * @return ResponseInterface
     * @throws \Psr\Http\Client\ClientExceptionInterface
     */
    private function makeRequest($hash): ResponseInterface
    {
        $uri = $this->uriFactory->createUri('https://api.pwnedpasswords.com/range/' . substr($hash, 0, 5));
        $request = $this->requestFactory->createRequest('GET', $uri);

        return $this->getClient()->sendRequest($request);
    }

    /**
     * @param $string
     *
     * @return string
     */
    private function getHash(string $string): string
    {
        return sha1($string);
    }

    /**
     * @param string $hash
     * @param string $responseBody
     *
     * @return string
     */
    private function getPasswordStatus($hash, $responseBody): string
    {
        $hash = strtoupper($hash);
        $hashSuffix = substr($hash, 5);

        $lines = explode("\r\n", $responseBody);

        foreach ($lines as $line) {
            [$exposedHashSuffix, $occurrences] = explode(':', $line);
            if (hash_equals($hashSuffix, $exposedHashSuffix)) {
                return PasswordStatus::EXPOSED;
            }
        }

        return PasswordStatus::NOT_EXPOSED;
    }
}
