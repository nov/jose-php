<?php

require_once dirname(__FILE__) . '/JWT.php';

class JOSE_JWS extends JOSE_JWT
{

    function __construct($jwt)
    {
        $this->header = $jwt->header;
        $this->claims = $jwt->claims;
        $this->signature = $jwt->signature;
        $this->raw = $jwt->raw;
    }

    function sign($private_key_or_secret, $algorithm = 'HS256')
    {
        $this->header['alg'] = $algorithm;
        $this->signature = $this->_sign($private_key_or_secret);
        if (!$this->signature) {
            throw new JOSE_Exception('Signing failed because of unknown reason');
        }
        return $this;
    }

    function verify($public_key_or_secret)
    {        
        if($this->_verify($public_key_or_secret)) {
            return $this;
        }

        throw new JOSE_Exception_VerificationFailed('Signature verification failed');
    }

    private function rsa($public_or_private_key, $padding_mode)
    {
        if($public_or_private_key instanceof JOSE_JWKSet) {
            
          return $this->rsaJwk($public_or_private_key, $padding_mode);
              
        } else {
            return $this->rsaClassic($public_or_private_key, $padding_mode);
        }
    }
    
    private function rsaJwk($jwkSet, $padding_mode)
    {
        $jwk = $jwkSet->filtreJwk("use", JOSE_JWK::JWK_USE_SIG, true);
        
        $alg = ($jwk->alg !== null) ? $jwk->alg : $this->digest();

        $modulus = new \Math_BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($jwk->n)), 16);
        $exponent = new \Math_BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($jwk->e)), 16);
        $rsa = new Crypt_RSA();
        $rsa->setSignatureMode($padding_mode);
        $rsa->setHash($alg);
        $rsa->modulus = $modulus;
        $rsa->exponent = $exponent;
        $rsa->publicExponent = $exponent;
        $rsa->k = strlen($rsa->modulus->toBytes());
        return $rsa;
    }            
    
    private function rsaClassic($public_or_private_key, $padding_mode)
    {
        $rsa = new Crypt_RSA();
        $rsa->loadKey($public_or_private_key);
        $rsa->setHash($this->digest());
        $rsa->setMGFHash($this->digest());
        $rsa->setSignatureMode($padding_mode);
        return $rsa;
    }

    private function digest()
    {
        switch ($this->header['alg']) {
            case 'HS256':
            case 'RS256':
            case 'ES256':
            case 'PS256':
                return 'sha256';
            case 'HS384':
            case 'RS384':
            case 'ES384':
            case 'PS384':
                return 'sha384';
            case 'HS512':
            case 'RS512':
            case 'ES512':
            case 'PS512':
                return 'sha512';
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
    }
    
    private function getPrivateKeyOrSecret($private_key_or_secret)
    {
        if($private_key_or_secret instanceof JOSE_JWKSet) {
            
            switch ($this->header['alg']) {
                case 'HS256':
                case 'HS384':
                case 'HS512':
                    return $private_key_or_secret->filtreJwk("use", JOSE_JWK::JWK_USE_SIG, true)->kid;
                case 'RS256':
                case 'RS384':
                case 'RS512':
                    return $private_key_or_secret;
                case 'ES256':
                case 'ES384':
                case 'ES512':
                    throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
                case 'PS256':
                case 'PS384':
                case 'PS512':
                    return $private_key_or_secret;
                default:
                    throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
            }
        }
        
        return $private_key_or_secret;
    }

    private function _sign($private_key_or_secret)
    {
        $signature_base_string = implode('.', array(
            $this->compact((object) $this->header),
            $this->compact((object) $this->claims)
        ));
        
        $private_key_or_secret = $this->getPrivateKeyOrSecret($private_key_or_secret);
        
        switch ($this->header['alg']) {
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return hash_hmac($this->digest(), $signature_base_string, $private_key_or_secret, true);
            case 'RS256':
            case 'RS384':
            case 'RS512':
                return $this->rsa($private_key_or_secret, CRYPT_RSA_SIGNATURE_PKCS1)->sign($signature_base_string);
            case 'ES256':
            case 'ES384':
            case 'ES512':
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
            case 'PS256':
            case 'PS384':
            case 'PS512':
                return $this->rsa($private_key_or_secret, CRYPT_RSA_SIGNATURE_PSS)->sign($signature_base_string);
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
    }

    private function _verify($public_key_or_secret)
    {
        $segments = explode('.', $this->raw);
        $signature_base_string = implode('.', array($segments[0], $segments[1]));
        switch ($this->header['alg']) {
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return $this->signature === hash_hmac($this->digest(), $signature_base_string, $public_key_or_secret, true);
            case 'RS256':
            case 'RS384':
            case 'RS512':
                return $this->rsa($public_key_or_secret, CRYPT_RSA_SIGNATURE_PKCS1)->verify($signature_base_string, $this->signature);
            case 'ES256':
            case 'ES384':
            case 'ES512':
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
            case 'PS256':
            case 'PS384':
            case 'PS512':
                return $this->rsa($public_key_or_secret, CRYPT_RSA_SIGNATURE_PSS)->verify($signature_base_string, $this->signature);
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
    }
}
