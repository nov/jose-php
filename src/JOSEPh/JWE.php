<?php

require_once dirname(__FILE__) . '/JWT.php';

class JOSEPh_JWE extends JOSEPh_JWT {
    var $plain_text;
    var $cipher_text;
    var $master_key;
    var $encrypted_master_key;
    var $encryption_key;
    var $integrity_key;
    var $iv;
    var $integrity_value;

    function __construct($input) {
        if ($input instanceof JOSEPh_JWT) {
            $this->raw = $input->toString();
        } else {
            $this->raw = $input;
        }
    }

    function encrypt($public_key_or_secret, $algorithm = 'RSA1_5', $encryption_method = 'A128CBC+HS256') {
        // NOTE:
        //  Encrypting something for native apps on server-side won't be a good idea in general.
        //  If you really do it, understand the concept of "Holder of Key (HoK)" first.
        //  I don't stop implementing this feature if you just want to use JWE for server-to-server communication.
        //  I think SSL is enough in that case though.
        throw new JOSEPh_Exception(
            'DO NOT ENCRYPT ANYTHING UNLESS UNDERSTANDING WHY ENCRYPTING IT USING WHAT KIND OF KEY FOR WHOM'
        );
    }

    function decrypt($private_key_or_secret) {
        $this->_decode();
        $this->decryptMasterKey($private_key_or_secret);
        $this->deriveEncryptionAndIntegrityKeys();
        $this->decryptCipherText();
        $this->checkIntegrity();
        return $this;
    }

    private function _decode() {
        $segments = explode('.', $this->raw);
        $this->header       = (array) $this->extract($segments[0]);
        $this->encrypted_master_key = $this->extract($segments[1], 'as_binary');
        $this->iv                   = $this->extract($segments[2], 'as_binary');
        $this->cipher_text          = $this->extract($segments[3], 'as_binary');
        $this->integrity_value      = $this->extract($segments[4], 'integrity_value');
        return $this;
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
                throw new JOSEPh_Exception_UnexpectedAlgorithm('Algorithm not supported');
            case 'A128CBC+HS256':
            case 'A256CBC+HS512':
                $cipher = new Crypt_AES(CRYPT_AES_MODE_CBC);
                break;
            default:
                throw new JOSEPh_Exception_UnexpectedAlgorithm('Unknown algorithm');
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
                throw new JOSEPh_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        return $cipher;
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
                throw new JOSEPh_Exception_UnexpectedAlgorithm('Algorithm not supported');
            default:
                throw new JOSEPh_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        if (!$this->master_key) {
            throw new JOSEPh_Exception_DecryptionFailed('Master key decryption failed');
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
                throw new JOSEPh_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        if (!$this->encryption_key || !$this->integrity_key) {
            throw new JOSEPh_Exception_DecryptionFailed('Encryption/Integrity key derivation failed');
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

    private function decryptCipherText() {
        $cipher = $this->cipher();
        $cipher->setKey($this->encryption_key);
        $cipher->setIV($this->iv);
        $this->plain_text = $cipher->decrypt($this->cipher_text);
        if (!$this->plain_text) {
            throw new JOSEPh_Exception_DecryptionFailed('Payload decryption failed');
        }
    }

    private function checkIntegrity() {
        # TODO
        throw new JOSEPh_Exception_VerificationFailed('Integrity check failed');
    }
}
