<?php

namespace DivineOmega\PasswordExposed;

use Doctrine\Common\Cache\FilesystemCache;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Kevinrob\GuzzleCache\CacheMiddleware;
use Kevinrob\GuzzleCache\Storage\DoctrineCacheStorage;
use Kevinrob\GuzzleCache\Strategy\PrivateCacheStrategy;

class PasswordExposedChecker
{
    private $client;

    public function __construct()
    {
        $stack = HandlerStack::create();

        $stack->push(
            new CacheMiddleware(
                new PrivateCacheStrategy(
                    new DoctrineCacheStorage(
                        new FilesystemCache(sys_get_temp_dir().'/pwned-passwords-cache')
                    )
                )
            ),
            'cache'
        );

        $this->client = new Client([
            'handler'  => $stack,
            'base_uri' => 'https://api.pwnedpasswords.com/',
            'timeout'  => 3.0,
        ]);
    }

    public function passwordExposed($password)
    {
        $hash = sha1($password);
        unset($password);

        $status = PasswordStatus::UNKNOWN;

        try {
            $status = $this->getPasswordStatus($hash, $this->makeRequest($hash));
        } catch (ConnectException $e) {
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
            if (hash_equals($hashSuffix, $exposedHashSuffix)) {
                return PasswordStatus::EXPOSED;
            }
        }

        return PasswordStatus::NOT_EXPOSED;
    }
}
