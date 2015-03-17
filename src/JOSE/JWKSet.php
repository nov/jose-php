<?php

/**
 * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31
 */
class JOSE_JWKSet
{

    var $keys;

    function __construct($keys = array())
    {
        if (!is_array($keys) || array_values($keys) !== $keys) {
            $keys = array($keys);
        }
        $this->keys = $keys;
    }

    function toString()
    {
        $keys = array();
        foreach ($this->keys as $key) {
            if ($key instanceof JOSE_JWK) {
                $keys[] = $key->components;
            } else {
                $keys[] = $key;
            }
        }
        return json_encode(array('keys' => $keys));
    }

    /**
     * @return array<JOSE_JWK>
     */
    public function getJwks()
    {
        return $this->keys;
    }

    /**
     * @param array<JOSE_JWK> $jwks
     */
    public function setJwks($jwks)
    {
        $this->keys = $jwks;
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
        foreach ($this->keys as $jwk) {

            if (array_key_exists($property, $jwk->components)) {
                if ($jwk->components[$property] == $value) {
                    $out[] = $jwk;
                }
            }
        }
        if (count($out) == 0) {
            $out = null;
        } elseif (count($out) == 1 || $unique == true) {
            $out = $out[0];
        }
        return $out;
    }

    /**
     * @param stdClass $key
     */
    private function addJsonKey(stdClass $key)
    {
        $jwkArray = array();
        foreach ($key as $keyName => $keyValue) {
            $this->standardiseKeyName($keyName);
            $jwkArray[$keyName] = $keyValue;
        }

        $this->keys[] = new JOSE_JWK($jwkArray);
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
