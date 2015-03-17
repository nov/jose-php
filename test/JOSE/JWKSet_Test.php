<?php

class JOSE_JWKSet_Test extends JOSE_TestCase {

    function setUp() {
        parent::setUp();
    }

    function testSetJsonObject() {
        $jsonText = file_get_contents($this->fixture_dir . 'op.jwk');
        $jsonObject = json_decode($jsonText);
        $jwks = new JOSE_JWKSet(array());
        $jwks->setJwksFromJsonObject($jsonObject);
        $jwksArray = $jwks->getJwks();
        
        $x5tS256 = "x5t#S256";
   
        $this->assertEquals($jsonObject->keys[0]->kty, $jwksArray[0]->components['kty']);
        $this->assertEquals($jsonObject->keys[0]->use, $jwksArray[0]->components['use']);
        $this->assertEquals($jsonObject->keys[0]->n, $jwksArray[0]->components['n']);
        $this->assertEquals($jsonObject->keys[0]->e, $jwksArray[0]->components['e']);
        $this->assertEquals($jsonObject->keys[0]->kid, $jwksArray[0]->components['kid']);
        $this->assertEquals($jsonObject->keys[0]->$x5tS256, $jwksArray[0]->components['x5tS256']);
    }

    function testJwkFilterObject() {
        $jsonText = file_get_contents($this->fixture_dir . 'opfilter.jwk');
        $jsonObject = json_decode($jsonText);
        $jwks = new JOSE_JWKSet();
        $jwks->setJwksFromJsonObject($jsonObject);
        
        $this->assertCount(2, $jwks->filterJwk("use", JOSE_JWK::JWK_USE_SIG));
        $this->assertNotNull($jwks->filterJwk("use", JOSE_JWK::JWK_USE_ENG));
        $this->assertFalse(is_array($jwks->filterJwk("use", JOSE_JWK::JWK_USE_ENG)));
        $this->assertInstanceOf("JOSE_JWK", $jwks->filterJwk("use", JOSE_JWK::JWK_USE_ENG));
        $this->assertInstanceOf("JOSE_JWK", $jwks->filterJwk("use", JOSE_JWK::JWK_USE_SIG, true));
    }
    
    function testJwkFilterObjectNullResult() {
        $jsonText = file_get_contents($this->fixture_dir . 'opfilter.jwk');
        $jsonObject = json_decode($jsonText);
        $jwks = new JOSE_JWKSet();
        $jwks->setJwksFromJsonObject($jsonObject);
        
        $this->assertNull($jwks->filterJwk("use", "dumb"));
    }

    function testJWKInput() {
        $key = new JOSE_JWK(array(
            'kty' => 'RSA',
            'e' => 'AQAB',
            'n' => 'x9vNhcvSrxjsegZAAo4OEuoZOV_oxINEeWneJYcz...'
        ));
        $jwks = new JOSE_JWKSet($key);
        $this->assertEquals('{"keys":[{"kty":"RSA","e":"AQAB","n":"x9vNhcvSrxjsegZAAo4OEuoZOV_oxINEeWneJYcz..."}]}', $jwks->toString());
    }

    function testArrayInput() {
        $key = array(
            'kty' => 'RSA',
            'e' => 'AQAB',
            'n' => 'x9vNhcvSrxjsegZAAo4OEuoZOV_oxINEeWneJYcz...'
        );
        $jwks = new JOSE_JWKSet($key);
        $this->assertEquals('{"keys":[{"kty":"RSA","e":"AQAB","n":"x9vNhcvSrxjsegZAAo4OEuoZOV_oxINEeWneJYcz..."}]}', $jwks->toString());
    }
}