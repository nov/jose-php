<?php

class JOSEPh_JWS_Test extends JOSEPh_TestCase {
    var $plain_jwt;
    var $rsa_keys;

    function setUp() {
        parent::setUp();
        $this->plain_jwt = new JOSEPh_JWT(array(
            'foo' => 'bar'
        ));
        $this->rsa_keys = array(
            'public' => file_get_contents($this->fixture_dir . 'public_key.pem'),
            'private' => file_get_contents($this->fixture_dir . 'private_key.pem')
        );
    }

    function testSignRS256() {
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.GzzxRgDHjgBjDkbMsKaFhWnQ43xKlh8T7Ce34b9ye4afuIfE2EglIlK1itGRx1PtH7UOcwtXVWElJ0lHuuTl6hCUL5SDOMJxiPfr5SkTZFWy2SlSYNtdRfra6NPeEa3-a_15dUYv41QY14TCl5HaP7jeMLeqcTlMcjra9fDPMWUciSyWay6025wUiSQBmWW-19GNZQnRHxXNX3lCVMEQMASYT-6QqBvoiJ6vezIt08RghgGdMH1iGY_Gnb7ISuA-lvKk6fcQvQ3MN5Cx0CeqXlXP8NQQF0OwkUgTjNGsKmCG6jKlLZLeXJb72KVK1yR-6jp7OQqqzrovIP7lp-FwIw';
        $jws = new JOSEPh_JWS($this->plain_jwt);
        $jws = $jws->sign($this->rsa_keys['private'], 'RS256');
        $this->assertEquals($expected, $jws->toString());
    }

    function testSignRS384() {
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJmb28iOiJiYXIifQ.Odg4nlRTnH1mI1JQEJEQCB1mmqDPFn-Gf5Te8IfLzu7sGDrvZdvGe6HutsDO3mXi7FLtQcI2i0KEQxj8fDUV4vfR1fbfyGQaz02qnt3HKEOgRGwFH1l57ayGChZftXhSCpbt9sMwTg1lsZ_egThQWG0ZErkibmXIt5ZxNwITaXX4oU3k12eH492IsScz_tIaf9NCwIQlAPodiVQL7WMQgej0o4LuZKk6ZgBsDJz_Ms2_iONxzGPWOT76iLOwYT8QaEsLX6d8_WsZ4wnfaxHVlg-zNM0Lhisi_F0_tFeueDOZPJnQp_InV7iYzP4adWOItzG_Qz_-EaNGTz4RJtxqAQ';
        $jws = new JOSEPh_JWS($this->plain_jwt);
        $jws = $jws->sign($this->rsa_keys['private'], 'RS384');
        $this->assertEquals($expected, $jws->toString());
    }

    function testSignRS512() {
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJmb28iOiJiYXIifQ.uQAVgGt1oy8FlMaAx8UDnVwzuDuJsqYIDHm8cKRKqLqcZ0zUmQHgfonBA09r5CiqG5EGTaX58G6_hAFAmf-aRtJrm_cN-68xrliMXVH3m6vZdRKhbtYqCozjbmEH8nPwBFtlri15vhR5lWTT_x3VsZOHhuhbAFzyshIcYAxNDVkUssPWpDag26fRcPsIJ-Oozvp9ld1uOnu9BNSOCWF4DXUTRBfUx55pl1ihwgHrFt36eHdtQ90vJXflsJvLoHuKf4LKt0dOpsPYeJp74V1X06DFlVqL9JGAS3iSLZ_tK_MpZheJqIr5iPl4qWc4k6gSbeomXR1opKqWmbje5JiZmw';
        $jws = new JOSEPh_JWS($this->plain_jwt);
        $jws = $jws->sign($this->rsa_keys['private'], 'RS512');
        $this->assertEquals($expected, $jws->toString());
    }

    function testSignRS256WithInvalidPrivateKey() {
        $jws = new JOSEPh_JWS($this->plain_jwt);
        $this->setExpectedException('JOSEPh_Exception');
        $jws = $jws->sign('invalid pem', 'RS256');
    }

    function testSignES256() {
        $jws = new JOSEPh_JWS($this->plain_jwt);
        $this->setExpectedException('JOSEPh_Exception_UnexpectedAlgorithm');
        $jws = $jws->sign('es key should be here', 'ES256');
    }

    function testSignUnknowAlg() {
        $jws = new JOSEPh_JWS($this->plain_jwt);
        $this->setExpectedException('JOSEPh_Exception_UnexpectedAlgorithm');
        $jws = $jws->sign('secret', 'AES256');
    }

    function testVerifyRS256() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.GzzxRgDHjgBjDkbMsKaFhWnQ43xKlh8T7Ce34b9ye4afuIfE2EglIlK1itGRx1PtH7UOcwtXVWElJ0lHuuTl6hCUL5SDOMJxiPfr5SkTZFWy2SlSYNtdRfra6NPeEa3-a_15dUYv41QY14TCl5HaP7jeMLeqcTlMcjra9fDPMWUciSyWay6025wUiSQBmWW-19GNZQnRHxXNX3lCVMEQMASYT-6QqBvoiJ6vezIt08RghgGdMH1iGY_Gnb7ISuA-lvKk6fcQvQ3MN5Cx0CeqXlXP8NQQF0OwkUgTjNGsKmCG6jKlLZLeXJb72KVK1yR-6jp7OQqqzrovIP7lp-FwIw';
        $jwt = JOSEPh_JWT::decode($input);
        $jws = new JOSEPh_JWS($jwt);
        $this->assertInstanceOf('JOSEPh_JWS', $jws->verify($this->rsa_keys['public']));
    }

    function testVerifyRS384() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJmb28iOiJiYXIifQ.Odg4nlRTnH1mI1JQEJEQCB1mmqDPFn-Gf5Te8IfLzu7sGDrvZdvGe6HutsDO3mXi7FLtQcI2i0KEQxj8fDUV4vfR1fbfyGQaz02qnt3HKEOgRGwFH1l57ayGChZftXhSCpbt9sMwTg1lsZ_egThQWG0ZErkibmXIt5ZxNwITaXX4oU3k12eH492IsScz_tIaf9NCwIQlAPodiVQL7WMQgej0o4LuZKk6ZgBsDJz_Ms2_iONxzGPWOT76iLOwYT8QaEsLX6d8_WsZ4wnfaxHVlg-zNM0Lhisi_F0_tFeueDOZPJnQp_InV7iYzP4adWOItzG_Qz_-EaNGTz4RJtxqAQ';
        $jwt = JOSEPh_JWT::decode($input);
        $jws = new JOSEPh_JWS($jwt);
        $this->assertInstanceOf('JOSEPh_JWS', $jws->verify($this->rsa_keys['public']));
    }

    function testVerifyRS512() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJmb28iOiJiYXIifQ.uQAVgGt1oy8FlMaAx8UDnVwzuDuJsqYIDHm8cKRKqLqcZ0zUmQHgfonBA09r5CiqG5EGTaX58G6_hAFAmf-aRtJrm_cN-68xrliMXVH3m6vZdRKhbtYqCozjbmEH8nPwBFtlri15vhR5lWTT_x3VsZOHhuhbAFzyshIcYAxNDVkUssPWpDag26fRcPsIJ-Oozvp9ld1uOnu9BNSOCWF4DXUTRBfUx55pl1ihwgHrFt36eHdtQ90vJXflsJvLoHuKf4LKt0dOpsPYeJp74V1X06DFlVqL9JGAS3iSLZ_tK_MpZheJqIr5iPl4qWc4k6gSbeomXR1opKqWmbje5JiZmw';
        $jwt = JOSEPh_JWT::decode($input);
        $jws = new JOSEPh_JWS($jwt);
        $this->assertInstanceOf('JOSEPh_JWS', $jws->verify($this->rsa_keys['public']));
    }

    function testVerifyES256() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.MEQCIDh9M3Id8pPd9fp6kgtirYpAirRCU-H0IbaeruLOYWc_AiBhbsswHCIlY5yqWDsOU_sy3lMnyXlrYoQLcejPxL-nDg';
        $jwt = JOSEPh_JWT::decode($input);
        $jws = new JOSEPh_JWS($jwt);
        $this->setExpectedException('JOSEPh_Exception_UnexpectedAlgorithm');
        $jws = $jws->verify('es key should be here');
    }

    function testVerifyUnknowAlg() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJ1bmtub3duIn0.eyJmb28iOiJiYXIifQ.';
        $jwt = JOSEPh_JWT::decode($input);
        $jws = new JOSEPh_JWS($jwt);
        $this->setExpectedException('JOSEPh_Exception_UnexpectedAlgorithm');
        $jws = $jws->verify('no key works');
    }
}