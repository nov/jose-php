<?php

class JOSE_JWK_Test extends JOSE_TestCase {
    function testConstructWithoutKTY() {
        $this->setExpectedException('JOSE_Exception_InvalidFormat');
        new JOSE_JWK(array('n' => 'n'));
    }

    function testToString() {
        $jwk = new JOSE_JWK(array('kty' => 'RSA', 'e' => 'e', 'n' => 'n'));
        $this->assertEquals('{"kty":"RSA","e":"e","n":"n"}', $jwk->toString());
    }

    function test__toString() {
        $jwk = new JOSE_JWK(array('kty' => 'RSA', 'e' => 'e', 'n' => 'n'));
        $this->assertEquals('{"kty":"RSA","e":"e","n":"n"}', sprintf('%s', $jwk));
    }

    function testEncodeRSAPublicKey() {
        $rsa = new Crypt_RSA();
        $rsa->loadKey($this->rsa_keys['public']);
        $jwk = JOSE_JWK::encode($rsa);
        $this->assertInstanceOf('JOSE_JWK', $jwk);
        $this->assertEquals('AQAB', $jwk->components['e']);
        $this->assertEquals('x9vNhcvSrxjsegZAAo4OEuoZOV_oxINEeWneJYczS80_bQ1J6lSSJ81qecxXAzCLPlvsFoP4eeUNXSt_G7hP7SAM479N-kY_MzbihJ5LRY9sRzLbQTMeqsmDAmmQe4y3Ke3bvd70r8VOmo5pqM3IPLGwBkTRTQmyRsDQArilg6WtxDUgy5ol2STHFA8E1iCReh9bck8ZaLxzVhYRXZ0nuOKWGRMppocPlp55HVohOItUZh7uSCchLcVAZuhTTNaDLtLIJ6G0yNJvfEieJUhA8wGBoPhD3LMQwQMxTMerpjZhP_qjm6GgeWpKf-iVil86_PSy_z0Vw06_rD0sfXPtlQ', $jwk->components['n']);
        $this->assertNotContains('d', $jwk->components);
    }

    function testEncodeRSAPrivateKey() {
        $rsa = new Crypt_RSA();
        $rsa->loadKey($this->rsa_keys['private']);
        $jwk = JOSE_JWK::encode($rsa);
        $this->assertInstanceOf('JOSE_JWK', $jwk);
        $this->assertEquals('AQAB', $jwk->components['e']);
        $this->assertEquals('x9vNhcvSrxjsegZAAo4OEuoZOV_oxINEeWneJYczS80_bQ1J6lSSJ81qecxXAzCLPlvsFoP4eeUNXSt_G7hP7SAM479N-kY_MzbihJ5LRY9sRzLbQTMeqsmDAmmQe4y3Ke3bvd70r8VOmo5pqM3IPLGwBkTRTQmyRsDQArilg6WtxDUgy5ol2STHFA8E1iCReh9bck8ZaLxzVhYRXZ0nuOKWGRMppocPlp55HVohOItUZh7uSCchLcVAZuhTTNaDLtLIJ6G0yNJvfEieJUhA8wGBoPhD3LMQwQMxTMerpjZhP_qjm6GgeWpKf-iVil86_PSy_z0Vw06_rD0sfXPtlQ', $jwk->components['n']);
        $this->assertEquals('S3xQjvVh-PJv9tK_gHeJB0nWBx6bewWdakI7Pm9nR30ZNKYtQc15eoESczhjsPe3z_DGJebohZmmx4bzNlQSFBzj4W1TFXFM05oqSi7DfV1jZyzlNSYKsjT0P4gBoziNwc9uDLPWNUFPo_6gF7rJo2r1chix-Oftpt2Sc0SsdyEESBMR5REMccX5gZIhN-DUTN4gt9GNeDRy9h-gNFxgNNtt17HzEg52gbl3UnEuuPXE2wcctE1nxT3WDdtVqb6nbaNfxLiaAWaL2uYBvU2_AvKu1b7VEPmP9pTEMyriVzh4Jb2ZtIUpna518M044GPKs1TgMHSAxpOaQvnpar9lrQ', $jwk->components['d']);
    }

    function testEncodeWithExtraComponents() {
        $rsa = new Crypt_RSA();
        $rsa->loadKey($this->rsa_keys['private']);
        $jwk = JOSE_JWK::encode($rsa, array(
            'kid' => '12345',
            'use' => 'sig'
        ));
        $this->assertEquals('12345', $jwk->components['kid']);
        $this->assertEquals('sig', $jwk->components['use']);
    }

    function testEncodeWithUnexpectedAlg() {
        $key = new Crypt_RC2();
        $this->setExpectedException('JOSE_Exception_UnexpectedAlgorithm');
        JOSE_JWK::encode($key);
    }

    function testDecodeRSAPublicKey() {
        $components = array(
            'kty' => 'RSA',
            'e' => 'AQAB',
            'n' => 'x9vNhcvSrxjsegZAAo4OEuoZOV_oxINEeWneJYczS80_bQ1J6lSSJ81qecxXAzCLPlvsFoP4eeUNXSt_G7hP7SAM479N-kY_MzbihJ5LRY9sRzLbQTMeqsmDAmmQe4y3Ke3bvd70r8VOmo5pqM3IPLGwBkTRTQmyRsDQArilg6WtxDUgy5ol2STHFA8E1iCReh9bck8ZaLxzVhYRXZ0nuOKWGRMppocPlp55HVohOItUZh7uSCchLcVAZuhTTNaDLtLIJ6G0yNJvfEieJUhA8wGBoPhD3LMQwQMxTMerpjZhP_qjm6GgeWpKf-iVil86_PSy_z0Vw06_rD0sfXPtlQ'
        );
        $key = JOSE_JWK::decode($components);
        $this->assertInstanceOf('Crypt_RSA', $key);
        $this->assertEquals(
            preg_replace("/\r\n|\r|\n/", '', $this->rsa_keys['public']),
            preg_replace("/\r\n|\r|\n/", '', $key->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_PKCS1_RAW))
        );
    }

    function testDecodeRSAPrivateKey() {
        $components = array(
            'kty' => 'RSA',
            'e' => 'AQAB',
            'n' => 'x9vNhcvSrxjsegZAAo4OEuoZOV_oxINEeWneJYczS80_bQ1J6lSSJ81qecxXAzCLPlvsFoP4eeUNXSt_G7hP7SAM479N-kY_MzbihJ5LRY9sRzLbQTMeqsmDAmmQe4y3Ke3bvd70r8VOmo5pqM3IPLGwBkTRTQmyRsDQArilg6WtxDUgy5ol2STHFA8E1iCReh9bck8ZaLxzVhYRXZ0nuOKWGRMppocPlp55HVohOItUZh7uSCchLcVAZuhTTNaDLtLIJ6G0yNJvfEieJUhA8wGBoPhD3LMQwQMxTMerpjZhP_qjm6GgeWpKf-iVil86_PSy_z0Vw06_rD0sfXPtlQ',
            'd' => 'S3xQjvVh-PJv9tK_gHeJB0nWBx6bewWdakI7Pm9nR30ZNKYtQc15eoESczhjsPe3z_DGJebohZmmx4bzNlQSFBzj4W1TFXFM05oqSi7DfV1jZyzlNSYKsjT0P4gBoziNwc9uDLPWNUFPo_6gF7rJo2r1chix-Oftpt2Sc0SsdyEESBMR5REMccX5gZIhN-DUTN4gt9GNeDRy9h-gNFxgNNtt17HzEg52gbl3UnEuuPXE2wcctE1nxT3WDdtVqb6nbaNfxLiaAWaL2uYBvU2_AvKu1b7VEPmP9pTEMyriVzh4Jb2ZtIUpna518M044GPKs1TgMHSAxpOaQvnpar9lrQ'
        );
        $this->setExpectedException('JOSE_Exception_UnexpectedAlgorithm');
        JOSE_JWK::decode($components);
    }

    function testDecodeWithUnexpectedAlg() {
        $components = array(
            'kty' => 'EC',
            'crv' => 'crv',
            'x' => 'x',
            'y' => 'y'
        );
        $this->setExpectedException('JOSE_Exception_UnexpectedAlgorithm');
        JOSE_JWK::decode($components);
    }
}