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
}
