<?php

class JOSE_Exception extends Exception {
}

require_once dirname(__FILE__) . '/Exception/DecryptionFailed.php';
require_once dirname(__FILE__) . '/Exception/InvalidFormat.php';
require_once dirname(__FILE__) . '/Exception/UnexpectedAlgorithm.php';
require_once dirname(__FILE__) . '/Exception/VerificationFailed.php';