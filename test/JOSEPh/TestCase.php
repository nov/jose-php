<?php

require_once 'PHPUnit/Autoload.php';
require_once dirname(__FILE__) . '/../../src/JOSEPh/JWT.php';

abstract class JOSEPh_TestCase extends PHPUnit_Framework_TestCase {
    var $fixture_dir;

    protected function setUp() {
        $this->fixture_dir = dirname(__FILE__) . '/../fixtures/';
    }
}
