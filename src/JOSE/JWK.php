<?php

/**
 * JWK
 *
 * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class JOSE_JWK
{
    const JWK_USE_SIG = "sig";
    const JWK_USE_ENG = "enc";
    
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.1
     * @var string (Key Type)
     */
    public $kty;
    
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.2
     * @var string (sig|enc|[other]) Public Key Use
     */
    public $use;
    
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.3
     * @var string  Key Operations
     */
    public $key_ops;
    
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.4
     * @var string Algorithm
     */
    public $alg;
    
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.5
     * @var string Key ID
     */
    public $kid;
    
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.6
     * @var string X.509 URL
     */
    public $x5u;
    
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.7
     * @var string X.509 Certificate Chain
     */
    public $x5c;
    
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.8
     * @var string X.509 Certificate SHA-1 Thumbprint
     */
    public $x5t;
    
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.9
     * @var string X.509 Certificate SHA-256 Thumbprint
     */
    public $x5tS256;

    /**
     * Use when kty = RSA
     * @var string 
     */
    public $n;
    
    /**
     * Use when kty = RSA
     * @var string 
     */
    public $e;

    var $components = array();

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

