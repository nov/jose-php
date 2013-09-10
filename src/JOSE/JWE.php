<?php

require_once dirname(__FILE__) . '/JWT.php';

class JOSE_JWE extends JOSE_JWT {
    var $plain_text;
    var $cipher_text;
    var $master_key;
    var $encrypted_master_key;
    var $encryption_key;
    var $integrity_key;
    var $iv;
    var $integrity_value;

    function __construct($input = null) {
        if ($input instanceof JOSE_JWT) {
            $this->raw = $input->toString();
        } else {
            $this->raw = $input;
        }
        unset($this->header['typ']);
    }

    function encrypt($public_key_or_secret, $algorithm = 'RSA1_5', $encryption_method = 'A128CBC+HS256') {
        $this->header['alg'] = $algorithm;
        $this->header['enc'] = $encryption_method;
        $this->plain_text = $this->raw;
        $this->generateMasterKey($public_key_or_secret);
        $this->encryptMasterKey($public_key_or_secret);
        $this->generateIv();
        $this->deriveEncryptionAndIntegrityKeys();
        $this->encryptCipherText();
        $this->generateIntegrityValue();
        return $this;
    }

    function decrypt($private_key_or_secret) {
        $this->decryptMasterKey($private_key_or_secret);
        $this->deriveEncryptionAndIntegrityKeys();
        $this->decryptCipherText();
        $this->checkIntegrity();
        return $this;
    }

    function toString() {
        return implode('.', array(
            $this->compact((object) $this->header),
            $this->compact($this->encrypted_master_key),
            $this->compact($this->iv),
            $this->compact($this->cipher_text),
            $this->compact($this->integrity_value)
        ));
    }

    private function rsa($public_or_private_key, $padding_mode) {
        $rsa = new Crypt_RSA();
        $rsa->loadKey($public_or_private_key);
        $rsa->setEncryptionMode($padding_mode);
        return $rsa;
    }

    private function cipher() {
        switch ($this->header['enc']) {
            case 'A128GCM':
            case 'A256GCM':
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
            case 'A128CBC+HS256':
            case 'A256CBC+HS512':
                $cipher = new Crypt_AES(CRYPT_AES_MODE_CBC);
                break;
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        switch ($this->header['enc']) {
            case 'A128GCM':
            case 'A128CBC+HS256':
                $cipher->setBlockLength(128);
                break;
            case 'A256GCM':
            case 'A256CBC+HS512':
                $cipher->setBlockLength(256);
                break;
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        return $cipher;
    }

    private function generateRandomBytes($length) {
        return crypt_random_string($length);
    }

    private function generateIv() {
        switch ($this->header['enc']) {
            case 'A128GCM':
            case 'A128CBC+HS256':
                $this->iv = $this->generateRandomBytes(128 / 8);
                break;
            case 'A256GCM':
            case 'A256CBC+HS512':
                $this->iv = $this->generateRandomBytes(256 / 8);
                break;
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
    }

    private function generateMasterKey($public_key_or_secret) {
        if ($this->header['alg'] == 'dir') {
            $this->master_key = $public_key_or_secret;
        } else {
            switch ($this->header['enc']) {
                case 'A128GCM':
                case 'A128CBC+HS256':
                    $this->master_key = $this->generateRandomBytes(128 / 8);
                    break;
                case 'A256GCM':
                case 'A256CBC+HS512':
                    $this->master_key = $this->generateRandomBytes(256 / 8);
                    break;
                default:
                    throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
            }
        }
    }

    private function encryptMasterKey($public_or_private_key) {
        switch ($this->header['alg']) {
            case 'RSA1_5':
                $rsa = $this->rsa($public_or_private_key, CRYPT_RSA_ENCRYPTION_PKCS1);
                $this->encrypted_master_key = $rsa->encrypt($this->master_key);
                break;
            case 'RSA-OAEP':
                $rsa = $this->rsa($public_or_private_key, CRYPT_RSA_ENCRYPTION_OAEP);
                $this->encrypted_master_key = $rsa->encrypt($this->master_key);
                break;
            case 'A128KW':
            case 'A256KW':
            case 'dir':
            case 'ECDH-ES':
            case 'ECDH-ES+A128KW':
            case 'ECDH-ES+A256KW':
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        if (!$this->master_key) {
            throw new JOSE_Exception_DecryptionFailed('Master key encryption failed');
        }
    }

    private function decryptMasterKey($public_or_private_key) {
        switch ($this->header['alg']) {
            case 'RSA1_5':
                $rsa = $this->rsa($public_or_private_key, CRYPT_RSA_ENCRYPTION_PKCS1);
                $this->master_key = $rsa->decrypt($this->encrypted_master_key);
                break;
            case 'RSA-OAEP':
                $rsa = $this->rsa($public_or_private_key, CRYPT_RSA_ENCRYPTION_OAEP);
                $this->master_key = $rsa->decrypt($this->encrypted_master_key);
                break;
            case 'A128KW':
            case 'A256KW':
            case 'dir':
            case 'ECDH-ES':
            case 'ECDH-ES+A128KW':
            case 'ECDH-ES+A256KW':
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        if (!$this->master_key) {
            throw new JOSE_Exception_DecryptionFailed('Master key decryption failed');
        }
    }

    private function deriveEncryptionAndIntegrityKeys() {
        switch ($this->header['enc']) {
            case 'A128GCM':
            case 'A256GCM':
                $this->encryption_key = $this->master_key;
                $this->integrity_key = "won't be used";
                break;
            case 'A128CBC+HS256':
                $this->deriveEncryptionAndIntegrityKeysCBC(256);
                break;
            case 'A256CBC+HS512':
                $this->deriveEncryptionAndIntegrityKeysCBC(512);
                break;
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        if (!$this->encryption_key || !$this->integrity_key) {
            throw new JOSE_Exception_DecryptionFailed('Encryption/Integrity key derivation failed');
        }
    }

    private function deriveEncryptionAndIntegrityKeysCBC($sha_size) {
        $encryption_key_size = $sha_size / 2;
        $integrity_key_size = $sha_size;
        $epu = isset($this->header['epu']) ? $this->header['epu'] : 0;
        $epv = isset($this->header['epv']) ? $this->header['epv'] : 0;
        $encryption_segments = array(
            pack('N*', 1),
            $this->master_key,
            pack('N*', $encryption_key_size),
            $this->header['enc'],
            pack('N*', $epu),
            pack('N*', $epv),
            'Encryption'
        );
        $integrity_segments = array(
            pack('N*', 1),
            $this->master_key,
            pack('N*', $integrity_key_size),
            $this->header['enc'],
            pack('N*', $epu),
            pack('N*', $epv),
            'Integrity'
        );
        $hash_function = new Crypt_Hash('sha' . $sha_size);
        $this->encryption_key = substr(
            $hash_function->hash(implode('', $encryption_segments)),
            0, $encryption_key_size / 8
        );
        $this->integrity_key = $hash_function->hash(implode('', $integrity_segments));
    }

    private function encryptCipherText() {
        $cipher = $this->cipher();
        $cipher->setKey($this->encryption_key);
        $cipher->setIV($this->iv);
        $this->cipher_text = $cipher->encrypt($this->plain_text);
        if (!$this->cipher_text) {
            throw new JOSE_Exception_DecryptionFailed('Payload encryption failed');
        }
    }

    private function decryptCipherText() {
        $cipher = $this->cipher();
        $cipher->setKey($this->encryption_key);
        $cipher->setIV($this->iv);
        $this->plain_text = $cipher->decrypt($this->cipher_text);
        if (!$this->plain_text) {
            throw new JOSE_Exception_DecryptionFailed('Payload decryption failed');
        }
    }

    private function generateIntegrityValue() {
        $this->integrity_value = $this->calculateIntegrityValue();
    }

    private function calculateIntegrityValue() {
        switch ($this->header['enc']) {
            case 'A128GCM':
            case 'A256GCM':
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
            case 'A128CBC+HS256':
                return $this->calculateIntegrityValueCBC(256);
            case 'A256CBC+HS512':
                return $this->calculateIntegrityValueCBC(512);
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
    }

    private function calculateIntegrityValueCBC($sha_size) {
        $secured_input = implode('.', array(
            $this->compact((object) $this->header),
            $this->compact($this->encrypted_master_key),
            $this->compact($this->iv),
            $this->compact($this->cipher_text)
        ));
        return hash_hmac('sha' . $sha_size, $secured_input, $this->integrity_key, true);
    }

    private function checkIntegrity() {
        switch ($this->header['enc']) {
            case 'A128GCM':
            case 'A256GCM':
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
            case 'A128CBC+HS256':
                return $this->integrity_value === $this->calculateIntegrityValueCBC(256);
            case 'A256CBC+HS512':
                return $this->integrity_value === $this->calculateIntegrityValueCBC(512);
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
    }
}
