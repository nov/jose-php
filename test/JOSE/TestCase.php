<?php

require_once 'PHPUnit/Autoload.php';
require_once dirname(__FILE__) . '/../../src/JOSE/JWT.php';

abstract class JOSE_TestCase extends PHPUnit_Framework_TestCase {
    var $fixture_dir;
    var $rsa_keys;

    protected function setUp() {
        $this->fixture_dir = dirname(__FILE__) . '/../fixtures/';
        $this->rsa_keys = array(
            'public' => file_get_contents($this->fixture_dir . 'public_key.pem'),
            'private' => file_get_contents($this->fixture_dir . 'private_key.pem')
        );
    }
}
