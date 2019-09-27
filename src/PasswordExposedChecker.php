<?php

namespace DivineOmega\PasswordExposed;

use DivineOmega\DOFileCachePSR6\CacheItemPool;
use DivineOmega\Psr18GuzzleAdapter\Client;
use GuzzleHttp\Exception\ConnectException;
use Http\Discovery\Psr17FactoryDiscovery;
use ParagonIE\Certainty\Bundle;
use ParagonIE\Certainty\Fetch;
use ParagonIE\Certainty\RemoteFetch;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;

/**
 * Class PasswordExposedChecker.
 */
class PasswordExposedChecker extends AbstractPasswordExposedChecker
{
    /** @var ClientInterface|null */
    protected $client;

    /** @var CacheItemPoolInterface|null */
    protected $cache;

    /** @var Bundle|null */
    protected $bundle;

    /** @var int|null */
    protected $cacheLifeTime;

    /** @var RequestFactoryInterface|null */
    protected $requestFactory;

    /** @var UriFactoryInterface|null */
    protected $uriFactory;

    /**
     * @param ClientInterface|null         $client
     * @param CacheItemPoolInterface|null  $cache
     * @param int|null                     $cacheLifeTime
     * @param RequestFactoryInterface|null $requestFactory
     * @param UriFactoryInterface|null     $uriFactory
     */
    public function __construct(
        ?ClientInterface $client = null,
        ?CacheItemPoolInterface $cache = null,
        ?int $cacheLifeTime = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?UriFactoryInterface $uriFactory = null
    ) {
        $this->client = $client;
        $this->cache = $cache;
        $this->cacheLifeTime = $cacheLifeTime;
        $this->requestFactory = $requestFactory;
        $this->uriFactory = $uriFactory;
    }

    /**
     * {@inheritdoc}
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

        return new Client($options);
    }

    /**
     * {@inheritdoc}
     */
    protected function getCache(): CacheItemPoolInterface
    {
        if ($this->cache === null) {
            $this->cache = $this->createCache();
        }

        return $this->cache;
    }

    /**
     * {@inheritdoc}
     */
    protected function getCacheLifeTime(): int
    {
        if ($this->cacheLifeTime === null) {
            return self::CACHE_EXPIRY_SECONDS;
        }

        return $this->cacheLifeTime;
    }

    /**
     * @return CacheItemPool
     */
    protected function createCache(): CacheItemPoolInterface
    {
        $cache = new CacheItemPool();
        $cache->changeConfig(
            [
                'cacheDirectory' => sys_get_temp_dir().'/password-exposed-cache/',
            ]
        );

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
     * {@inheritdoc}
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
     * @param Bundle $bundle
     */
    public function setBundle(Bundle $bundle): void
    {
        $this->bundle = $bundle;
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
     * @throws \ParagonIE\Certainty\Exception\CertaintyException
     * @throws \SodiumException
     *
     * @return Bundle
     */
    protected function getBundleFromCertainty(): Bundle
    {
        $ourCertaintyDataDir = __DIR__.'/../bundles';

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
        try {
            // Try the replication server first, since the upstream server
            // is under tremendous load.
            return (new RemoteFetch($ourCertaintyDataDir))
                ->setChronicle(
                    'https://php-chronicle-replica.pie-hosted.com/chronicle/replica/_vi6Mgw6KXBSuOFUwYA2H2GEPLawUmjqFJbCCuqtHzGZ',
                    'MoavD16iqe9-QVhIy-ewD4DMp0QRH-drKfwhfeDAUG0='
                )
                ->getLatestBundle();
        } catch (ConnectException $ex) {
            // Fallback to the main server.
            return (new RemoteFetch($ourCertaintyDataDir))->getLatestBundle();
        }
    }
}
