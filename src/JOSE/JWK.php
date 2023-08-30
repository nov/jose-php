<?php

use phpseclib3\Crypt\RSA;
use phpseclib3\Math\BigInteger;
use phpseclib3\Crypt\Hash;
use phpseclib3\Crypt\RSA\Formats\Keys\PKCS8;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;

class JOSE_JWK {
    var $components = array();

    function __construct($components = array()) {
        if (!array_key_exists('kty', $components)) {
            throw new JOSE_Exception_InvalidFormat('"kty" is required');
        }
        $this->components = $components;
        if (!array_key_exists('kid', $this->components)) {
            $this->components['kid'] = $this->thumbprint();
        }
    }

    function toKey() {
        switch ($this->components['kty']) {
            case 'RSA':
                $n = new BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($this->components['n'])), 16);
                $e = new BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($this->components['e'])), 16);
                if (array_key_exists('d', $this->components)) {
                    throw new JOSE_Exception_UnexpectedAlgorithm('RSA private key isn\'t supported');
                } else {
                    $pem_string = PKCS8::savePublicKey($n, $e);
                }
                return RSA::load($pem_string);
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown key type');
        }
    }

    function thumbprint($hash_algorithm = 'sha256') {
        $hash = new Hash($hash_algorithm);
        return JOSE_URLSafeBase64::encode(
            $hash->hash(
                json_encode($this->normalized())
            )
        );
    }

    private function normalized() {
        switch ($this->components['kty']) {
            case 'RSA':
                return array(
                    'e'   => $this->components['e'],
                    'kty' => $this->components['kty'],
                    'n'   => $this->components['n']
                );
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown key type');
        }
    }

    function toString() {
        return json_encode($this->components);
    }
    function __toString() {
        return $this->toString();
    }

    static function encode($key, $extra_components = array()) {
        switch(true) {
            case $key instanceof RSA:
                switch(true) {
                    case $key instanceof PrivateKey:
                        $resource = openssl_pkey_get_private($key->toString('PKCS8'));
                        break;
                    case $key instanceof PublicKey:
                        $resource = openssl_pkey_get_public($key->toString('PKCS8'));
                        break;
                }
                $details = openssl_pkey_get_details($resource);
                $components = array(
                    'kty' => 'RSA',
                    'e' => JOSE_URLSafeBase64::encode($details['rsa']['e']),
                    'n' => JOSE_URLSafeBase64::encode($details['rsa']['n'])
                );
                if ($key instanceof PrivateKey) {
                    $components = array_merge($components, array(
                        'd' => JOSE_URLSafeBase64::encode($details['rsa']['d'])
                    ));
                }
                return new self(array_merge($components, $extra_components));
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown key type');
        }
    }

    static function decode($components) {
        $jwk = new self($components);
        return $jwk->toKey();
    }
}