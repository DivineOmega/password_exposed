<?php

namespace DivineOmega\PasswordExposed;

use DivineOmega\PasswordExposed\Enums\PasswordStatus;
use DivineOmega\PasswordExposed\Interfaces\PasswordExposedCheckerInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriFactoryInterface;

/**
 * Class AbstractPasswordExposedChecker.
 */
abstract class AbstractPasswordExposedChecker implements PasswordExposedCheckerInterface
{
    /** @var int */
    protected const CACHE_EXPIRY_SECONDS = 2592000;

    /**
     * {@inheritdoc}
     */
    public function passwordExposed(string $password): string
    {
        return $this->passwordExposedByHash($this->getHash($password));
    }

    /**
     * {@inheritdoc}
     */
    public function passwordExposedByHash(string $hash): string
    {
        $cache = $this->getCache();
        $cacheKey = substr($hash, 0, 2).'_'.substr($hash, 2, 3);
        $body = null;

        try {
            $cacheItem = $cache->getItem($cacheKey);

            // try to get status from cache
            if ($cacheItem->isHit()) {
                $body = $cacheItem->get();
            }
        } catch (\Exception $e) {
            $cacheItem = null;
        }

        // get status from api
        if ($body === null) {
            try {
                /** @var ResponseInterface $response */
                $response = $this->makeRequest($hash);

                /** @var string $responseBody */
                $body = $response->getBody()->getContents();

                // cache status
                if ($cacheItem !== null) {
                    $cacheLifeTime = $this->getCacheLifeTime();

                    if ($cacheLifeTime <= 0) {
                        $cacheLifeTime = self::CACHE_EXPIRY_SECONDS;
                    }

                    $cacheItem->set($body);
                    $cacheItem->expiresAfter($cacheLifeTime);
                    $cache->save($cacheItem);
                }
            } catch (ClientExceptionInterface $e) {
            }
        }

        if ($body === null) {
            return PasswordExposedCheckerInterface::UNKNOWN;
        }

        return $this->getPasswordStatus($hash, $body);
    }

    /**
     * {@inheritdoc}
     */
    public function isExposed(string $password): ?bool
    {
        return $this->isExposedByHash($this->getHash($password));
    }

    /**
     * {@inheritdoc}
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
     * @throws \Psr\Http\Client\ClientExceptionInterface
     *
     * @return ResponseInterface
     */
    protected function makeRequest(string $hash): ResponseInterface
    {
        $uri = $this->getUriFactory()->createUri('https://api.pwnedpasswords.com/range/'.substr($hash, 0, 5));
        $request = $this->getRequestFactory()->createRequest('GET', $uri);

        return $this->getClient()->sendRequest($request);
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
            list($exposedHashSuffix, $occurrences) = explode(':', $line);
            if (hash_equals($hashSuffix, $exposedHashSuffix)) {
                return PasswordStatus::EXPOSED;
            }
        }

        return PasswordStatus::NOT_EXPOSED;
    }

    /**
     * @return ClientInterface
     */
    abstract protected function getClient(): ClientInterface;

    /**
     * @return CacheItemPoolInterface
     */
    abstract protected function getCache(): CacheItemPoolInterface;

    /**
     * @return int
     */
    abstract protected function getCacheLifeTime(): int;

    /**
     * @return RequestFactoryInterface
     */
    abstract protected function getRequestFactory(): RequestFactoryInterface;

    /**
     * @return UriFactoryInterface
     */
    abstract protected function getUriFactory(): UriFactoryInterface;
}
