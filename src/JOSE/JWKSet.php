<?php

/**
 * JWKSet 
 * Set ok JOSE_JWK
 *
 * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class JOSE_JWKSet
{
   /**
    * @var array<JOSE_JWK>
    */
   private $jwks;
   
   public function __construct()
   {
       $this->jwks = array();
   }

   /**
    * @return array<JOSE_JWK>
    */
   public function getJwks()
   {
       return $this->jwks;
   }
   
   /**
    * @param array<JOSE_JWK> $jwks
    */
   public function setJwks($jwks)
   {
       $this->jwks = $jwks;
   }
   /**
    * @param array<JOSE_JWK> $jwks
    */
    public function setJwksFromJsonObject($jwksJson)
    {
        $keys = $jwksJson->keys;
        foreach ($keys as $key) {
            $this->addJsonKey($key);
        }
    }

    /**
     * 
     * @param string $property JWK property name
     * @param string $value a value
     * @param boolean $unique return a unique result or many
     */
    public function filterJwk($property, $value, $unique = false)
    {
        $out = array();
        foreach($this->jwks as $jwk) {
            if(property_exists($jwk, $property)) {
                if($jwk->$property == $value) {
                    $out[] = $jwk;
                }
            }
        }
        
        if(count($out) == 1 || $unique == true) {
            return $out[0];
        }
        return $out;
    }

    /**
     * @param stdClass $key
     */
    private function addJsonKey(stdClass $key)
    {        
        $jwk = new JOSE_JWK();
        foreach($key as $keyName => $keyValue) {
            $this->standardiseKeyName($keyName);
            
            if(property_exists ($jwk , $keyName )) {
                $jwk->$keyName = $keyValue;
            }
        }
        $this->jwks[] = $jwk;
    }
    
    private function standardiseKeyName(&$keyName)
    {
        $keyName = str_replace("#", "", $keyName);
    }

    /**
     * 
     * @param string $n RSA modulus
     * @param string $e RSA exponent
     * @param string $kid Key ID
     * @param string $alg Algorithm
     */
   public function addRSAKeyType($n, $e, $kid, $alg = null)
   {
       $jws = new JOSE_JWK();
       $jws->kty = "RSA";
       $jws->n = $n;
       $jws->e = $e;
       $jws->kid = $kid;
       $jws->alg = $alg;
       
       $this->jwks[] = $jws;
   }
}
