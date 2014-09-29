<?php

class JOSE_JWK {
    var $components = array();

    function __construct($components = array()) {
        $this->components = $components;
    }

    function toString() {
        return json_encode($this->components);
    }

    static function encode($key, $extra_components = array()) {
        switch(get_class($key)) {
            case 'Crypt_RSA':
                $components = array(
                    'kty' => 'RSA',
                    'e' => JOSE_URLSafeBase64::encode($key->publicExponent->toBytes()),
                    'n' => JOSE_URLSafeBase64::encode($key->modulus->toBytes())
                );
                if ($key->exponent != $key->publicExponent) {
                    $components = array_merge($components, array(
                        'd' => JOSE_URLSafeBase64::encode($key->exponent->toBytes())
                    ));
                }
                return new self(array_merge($components, $extra_components));
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown key type');
        }
    }

    static function decode($components) {
        throw new JOSE_Exception_UnexpectedAlgorithm('Not implemented yet');
    }
}