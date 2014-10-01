<?php

/**
 * JWK
 * 
 * Properties defined in specification :
 *  - kty :     string, Key Type
 *  - use :     string, sig|enc|[other] Public Key Use
 *  - key_ops : string, Key Operations
 *  - alg :     string, Algorithm
 *  - kid :     string, Key ID
 *  - x5u :     string, X.509 URL
 *  - x5c :     string, X.509 Certificate Chain
 *  - x5t :     string, X.509 Certificate SHA-1 Thumbprint
 *  - x5t#S256 : string, X.509 Certificate SHA-256 Thumbprint
 *  - n :       string, to use when kty = RSA
 *  - e :       string, to use when kty = RSA
 *
 * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31
 */
class JOSE_JWK
{
    const JWK_USE_SIG = "sig";
    const JWK_USE_ENG = "enc";

    public $components = array();

    function __construct($components = array()) {
        if (!array_key_exists('kty', $components)) {
            throw new JOSE_Exception_InvalidFormat('"kty" is required');
        }
        $this->components = $components;
    }

    function toKey() {
        switch ($this->components['kty']) {
            case 'RSA':
                $rsa = new Crypt_RSA();
                $n = new Math_BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($this->components['n'])), 16);
                $e = new Math_BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($this->components['e'])), 16);
                if (array_key_exists('d', $this->components)) {
                    throw new JOSE_Exception_UnexpectedAlgorithm('RSA private key isn\'t supported');
                } else {
                    $pem_string = $rsa->_convertPublicKey($n, $e);
                }
                $rsa->loadKey($pem_string);
                return $rsa;
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown key type');
        }
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
        $jwk = new self($components);
        return $jwk->toKey();
    }
}

