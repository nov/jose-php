<?php

class JOSEPh_JWT_Test extends JOSEPh_TestCase {
    function testToStringWithBlankClaims() {
        # NOTE:
        #  PHP isn't good at handling blank JSON object.
        #  json_encode(array()) => '[]'
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.e30.';
        $jwt = new JOSEPh_JWT();
        $this->assertEquals($expected, $jwt->toString());
    }

    function testToStringWithConnectClaims() {
        # NOTE:
        #  PHP converts '/' to '\/' in JSON, it can be different in other languages.
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJncmVlLXVpZC0xMjM0NSIsImlzcyI6Imh0dHBzOlwvXC9ncmVlLm5ldCIsImF1ZCI6ImdyZWUtYXBwaWQtMTIzNDUifQ.';
        $jwt = new JOSEPh_JWT(array(
            'sub' => 'gree-uid-12345',
            'iss' => 'https://gree.net',
            'aud' => 'gree-appid-12345'
        ));
        $this->assertEquals($expected, $jwt->toString());
    }

    function testEncode() {
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJncmVlLXVpZC0xMjM0NSIsImlzcyI6Imh0dHBzOlwvXC9ncmVlLm5ldCIsImF1ZCI6ImdyZWUtYXBwaWQtMTIzNDUifQ.';
        $jwt = JOSEPh_JWT::encode(array(
            'sub' => 'gree-uid-12345',
            'iss' => 'https://gree.net',
            'aud' => 'gree-appid-12345'
        ));
        $this->assertEquals($expected, $jwt->toString());
    }

    function testDecode() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIiwiZm9vIjoiZm9vIn0.eyJzdWIiOiJncmVlLXVpZC0xMjM0NSIsImlzcyI6Imh0dHBzOlwvXC9ncmVlLm5ldCIsImF1ZCI6ImdyZWUtYXBwaWQtMTIzNDUifQ.';
        $expected = array(
            'header' => array(
                'typ' => 'JWT',
                'alg' => 'none',
                'foo' => 'foo'
            ),
            'claims' => array(
                'sub' => 'gree-uid-12345',
                'iss' => 'https://gree.net',
                'aud' => 'gree-appid-12345'
            )
        );
        $jwt = JOSEPh_JWT::decode($input);
        $this->assertEquals($expected['header'], (array) $jwt->header);
        $this->assertEquals($expected['claims'], (array) $jwt->claims);
    }

    function testDecodeWithTooManyDots() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIiwiZm9vIjoiZm9vIn0.eyJzdWIiOiJncmVlLXVpZC0xMjM0NSIsImlzcyI6Imh0dHBzOlwvXC9ncmVlLm5ldCIsImF1ZCI6ImdyZWUtYXBwaWQtMTIzNDUifQ..';
        $this->setExpectedException('JOSEPh_Exception_InvalidFormat');
        JOSEPh_JWT::decode($input);
    }

    function testDecodeWithTooFewDots() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIiwiZm9vIjoiZm9vIn0.eyJzdWIiOiJncmVlLXVpZC0xMjM0NSIsImlzcyI6Imh0dHBzOlwvXC9ncmVlLm5ldCIsImF1ZCI6ImdyZWUtYXBwaWQtMTIzNDUifQ';
        $this->setExpectedException('JOSEPh_Exception_InvalidFormat');
        JOSEPh_JWT::decode($input);
    }

    function testDecodeWithInvalidSerialization() {
        $input = 'header.payload.signature';
        $this->setExpectedException('JOSEPh_Exception_InvalidFormat');
        JOSEPh_JWT::decode($input);
    }

    function testSign() {
        $expected = array(
            'jwt' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.',
            'jws' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.bVhBeMrW5g33Vi4FLSLn7aqcmAiupmmw-AY17YxCYLI'
        );
        $expected_with_signature = '';
        $jwt = new JOSEPh_JWT(array(
            'foo' => 'bar'
        ));
        $jws = $jwt->sign('secret');
        $this->assertEquals($expected['jwt'], $jwt->toString()); // no signature for the original $jwt object
        $this->assertEquals($expected['jws'], $jws->toString());
    }

    function testVerify() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.bVhBeMrW5g33Vi4FLSLn7aqcmAiupmmw-AY17YxCYLI';
        $jwt = JOSEPh_JWT::decode($input);
        $this->assertInstanceOf('JOSEPh_JWS', $jwt->verify('secret'));
    }

    function testVerifyInvalid() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.bVhBeMrW5g33Vi4FLSLn7aqcmAiupmmw-AY17YxCYLI-invalid';
        $jwt = JOSEPh_JWT::decode($input);
        $this->setExpectedException('JOSEPh_Exception_VerificationFailed');
        $res = $jwt->verify('secret');
        var_dump($res);
    }
}
