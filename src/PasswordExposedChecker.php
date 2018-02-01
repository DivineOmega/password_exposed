<?php

namespace DivineOmega\PasswordExposed;

use Exception;
use GuzzleHttp\Client;

class PasswordExposedChecker
{   
    private $client;

    public function __construct()
    {
        $this->client = new Client([
            'base_uri' => 'https://haveibeenpwned.com/api/v2/',
            'timeout' => 3.0
        ]);
    }

    public function passwordExposed($password)
    {
        $hash = sha1($password);
        unset($password);

        sleep(2);

        $response = $this->makeRequest($hash);

        switch($response->getStatusCode()) {
            case 200: 
                return true;

            case 404:
                return false;
        }

        $responseBody = (string) $response->getBody();

        throw new Exception('Unexpected response from password exposed check: '.$responseBody);
    }

    private function makeRequest($hash)
    {
        $options = [
            'exceptions' => false,
            'headers' => [
                'User_Agent' => 'password_exposed - https://github.com/DivineOmega/password_exposed'
            ]
        ];

        return $this->client->request('GET', 'pwnedpassword/'.$hash, $options);
    }
}