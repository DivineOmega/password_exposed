<?php

namespace DivineOmega\PasswordExposed;

use DivineOmega\DOFileCachePSR6\CacheItemPool;
use Http\Adapter\Guzzle6\Client as GuzzleAdapter;
use Http\Discovery\Psr17FactoryDiscovery;
use ParagonIE\Certainty\Bundle;
use ParagonIE\Certainty\Fetch;
use ParagonIE\Certainty\RemoteFetch;
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
class PasswordExposedChecker implements PasswordExposedCheckerInterface
{

    /** @var ClientInterface|null */
    protected $client;

    /** @var CacheItemPoolInterface|null */
    protected $cache;

    /** @var Bundle|null */
    protected $bundle;

    /** @var RequestFactoryInterface|null */
    protected $requestFactory;

    /** @var UriFactoryInterface|null */
    protected $uriFactory;

    /** @var int */
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
        $this->requestFactory = $requestFactory;
        $this->uriFactory = $uriFactory;
    }

    /**
     * @inheritdoc
     */
    public function passwordExposed(string $password): string
    {
        return $this->passwordExposedByHash($this->getHash($password));
    }

    /**
     * @inheritdoc
     */
    public function passwordExposedByHash(string $hash): string
    {
        $cacheKey = substr($hash, 0, 2) . '_' . substr($hash, 2, 3);

        try {
            $cacheItem = $this->getCache()->getItem($cacheKey);
        } catch (\Exception $e) {
            $cacheItem = null;
        }

        if ($cacheItem !== null && $cacheItem->isHit()) {
            /** @var string $responseBody */
            $responseBody = $cacheItem->get();
        } else {
            try {
                /** @var ResponseInterface $response */
                $response = $this->makeRequest($hash);

                if ($response->getStatusCode() !== 200) {
                    return PasswordExposedCheckerInterface::UNKNOWN;
                }
            } catch (ClientExceptionInterface $e) {
                return PasswordExposedCheckerInterface::UNKNOWN;
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
     * @inheritdoc
     */
    public function isExposed(string $password): ?bool
    {
        return $this->isExposedByHash($this->getHash($password));
    }

    /**
     * @inheritdoc
     */
    public function isExposedByHash(string $hash): ?bool
    {
        $status = $this->passwordExposedByHash($hash);

        if ($status === PasswordExposedCheckerInterface::EXPOSED) {
            return true;
        }

        if ($status === PasswordExposedCheckerInterface::NOT_EXPOSED) {
            return false;
        }

        return null;
    }

    /**
     * @param $hash
     *
     * @return ResponseInterface
     * @throws \Psr\Http\Client\ClientExceptionInterface
     */
    protected function makeRequest(string $hash): ResponseInterface
    {
        $uri = $this->getUriFactory()->createUri('https://api.pwnedpasswords.com/range/' . substr($hash, 0, 5));
        $request = $this->getRequestFactory()->createRequest('GET', $uri);

        return $this->getClient()->sendRequest($request);
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
     * @return RequestFactoryInterface
     */
    protected function getRequestFactory(): RequestFactoryInterface
    {
        if ($this->requestFactory === null) {
            $this->requestFactory = $this->createRequestFactory();
        }

        return $this->requestFactory;
    }

    /**
     * @return RequestFactoryInterface
     */
    protected function createRequestFactory(): RequestFactoryInterface
    {
        return Psr17FactoryDiscovery::findRequestFactory();
    }

    /**
     * @return UriFactoryInterface
     */
    protected function getUriFactory(): UriFactoryInterface
    {
        if ($this->uriFactory === null) {
            $this->uriFactory = $this->createUriFactory();
        }

        return $this->uriFactory;
    }

    /**
     * @return UriFactoryInterface
     */
    protected function createUriFactory(): UriFactoryInterface
    {
        return Psr17FactoryDiscovery::findUrlFactory();
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
     * @throws \ParagonIE\Certainty\Exception\CertaintyException
     * @throws \SodiumException
     */
    protected function getBundleFromCertainty(): Bundle
    {
        $ourCertaintyDataDir = __DIR__ . '/../bundles';

        if (!is_writable($ourCertaintyDataDir)) {

            // If we can't write to the our Certainty data directory, just
            // use the latest bundle from the Certainty package.
            return (new Fetch($ourCertaintyDataDir))->getLatestBundle();
        }

        if (PHP_INT_SIZE === 4 && !extension_loaded('sodium')) {

            // If the platform would run verification checks slowly, use the
            // latest bundle from the Certainty package and disable verification.
            return (new Fetch($ourCertaintyDataDir))->getLatestBundle(false, false);
        }

        // If the platform can run verification checks well enough, get
        // latest remote bundle and verify it.
        return (new RemoteFetch($ourCertaintyDataDir))->getLatestBundle();
    }

    /**
     * @param $string
     *
     * @return string
     */
    protected function getHash(string $string): string
    {
        return sha1($string);
    }

    /**
     * @param string $hash
     * @param string $responseBody
     *
     * @return string
     */
    protected function getPasswordStatus($hash, $responseBody): string
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
