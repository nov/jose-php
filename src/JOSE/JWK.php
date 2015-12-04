<?php

use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;
use phpseclib\Crypt\Hash;

class JOSE_JWK {
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
                $rsa = new RSA();
                $n = new BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($this->components['n'])), 16);
                $e = new BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($this->components['e'])), 16);
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
    function __toString() {
        return $this->toString();
    }

    static function encode($key, $extra_components = array()) {
        switch(get_class($key)) {
            case 'phpseclib\Crypt\RSA':
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
    
    /** 
     * Returns the JWK Thumbprint of the Json Web Key
     * see https://tools.ietf.org/html/rfc7638
     */
    function thumbprint() {
      $requiredcomp=array();
      switch ($this->components['kty']) {
        case 'RSA':
	  $requiredcomp=array("e"=>$this->components["e"],
			      "kty"=>"RSA",
			      "n"=>$this->components["n"]
			      ); // ORDER MATTERS as required by RFC !
        default:
	  throw new JOSE_Exception_UnexpectedAlgorithm('Unknown key type');
      }     
      $hash = new Hash('sha256');
      return JOSE_URLSafeBase64::encode(
					$hash->hash( json_encode( $requiredcomp ) )
					);
    }
    
}