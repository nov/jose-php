<?php

namespace test;

abstract class JOSETestCase extends \PHPUnit\Framework\TestCase
{
    protected $fixture_dir;
    protected $rsa_keys;

    protected function setUp(): void
    {
        $this->fixture_dir = __DIR__ . '/fixtures/';
        $this->rsa_keys = array(
            'public' => file_get_contents($this->fixture_dir . 'public_key.pem'),
            'private' => file_get_contents($this->fixture_dir . 'private_key.pem')
        );
    }
}
