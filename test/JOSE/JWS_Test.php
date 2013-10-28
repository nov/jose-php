<?php

class JOSE_JWS_Test extends JOSE_TestCase {
    var $plain_jwt;
    var $rsa_keys;

    function setUp() {
        parent::setUp();
        $this->plain_jwt = new JOSE_JWT(array(
            'foo' => 'bar'
        ));

    }

    function testSignHS256() {
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.jBKXM6zRu0nP2tYgNTgFxRDwKoiEbNl1P6GyXEHIwEw';
        $jws = new JOSE_JWS($this->plain_jwt);
        $jws = $jws->sign('shared-secret', 'HS256');
        $this->assertEquals($expected, $jws->toString());
    }

    function testSignHS384() {
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJmb28iOiJiYXIifQ.EoHJwaBtAB7OQzhInUDK5QBrKqhYX8OodiAgusI3fOJsueTm6aOpKvngGj3afGQo';
        $jws = new JOSE_JWS($this->plain_jwt);
        $jws = $jws->sign('shared-secret', 'HS384');
        $this->assertEquals($expected, $jws->toString());
    }

    function testSignHS512() {
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJmb28iOiJiYXIifQ.eLwaujbDB1c19eOGpxwMksVHCkE5XLA4eps80ZDPAE8_FdQOMQvC6lF0mtAHljAai9XHEDWMXUz1NCeovs8ZVQ';
        $jws = new JOSE_JWS($this->plain_jwt);
        $jws = $jws->sign('shared-secret', 'HS512');
        $this->assertEquals($expected, $jws->toString());
    }

    function testSignRS256() {
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.GzzxRgDHjgBjDkbMsKaFhWnQ43xKlh8T7Ce34b9ye4afuIfE2EglIlK1itGRx1PtH7UOcwtXVWElJ0lHuuTl6hCUL5SDOMJxiPfr5SkTZFWy2SlSYNtdRfra6NPeEa3-a_15dUYv41QY14TCl5HaP7jeMLeqcTlMcjra9fDPMWUciSyWay6025wUiSQBmWW-19GNZQnRHxXNX3lCVMEQMASYT-6QqBvoiJ6vezIt08RghgGdMH1iGY_Gnb7ISuA-lvKk6fcQvQ3MN5Cx0CeqXlXP8NQQF0OwkUgTjNGsKmCG6jKlLZLeXJb72KVK1yR-6jp7OQqqzrovIP7lp-FwIw';
        $jws = new JOSE_JWS($this->plain_jwt);
        $jws = $jws->sign($this->rsa_keys['private'], 'RS256');
        $this->assertEquals($expected, $jws->toString());
    }

    function testSignRS384() {
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJmb28iOiJiYXIifQ.Odg4nlRTnH1mI1JQEJEQCB1mmqDPFn-Gf5Te8IfLzu7sGDrvZdvGe6HutsDO3mXi7FLtQcI2i0KEQxj8fDUV4vfR1fbfyGQaz02qnt3HKEOgRGwFH1l57ayGChZftXhSCpbt9sMwTg1lsZ_egThQWG0ZErkibmXIt5ZxNwITaXX4oU3k12eH492IsScz_tIaf9NCwIQlAPodiVQL7WMQgej0o4LuZKk6ZgBsDJz_Ms2_iONxzGPWOT76iLOwYT8QaEsLX6d8_WsZ4wnfaxHVlg-zNM0Lhisi_F0_tFeueDOZPJnQp_InV7iYzP4adWOItzG_Qz_-EaNGTz4RJtxqAQ';
        $jws = new JOSE_JWS($this->plain_jwt);
        $jws = $jws->sign($this->rsa_keys['private'], 'RS384');
        $this->assertEquals($expected, $jws->toString());
    }

    function testSignRS512() {
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJmb28iOiJiYXIifQ.uQAVgGt1oy8FlMaAx8UDnVwzuDuJsqYIDHm8cKRKqLqcZ0zUmQHgfonBA09r5CiqG5EGTaX58G6_hAFAmf-aRtJrm_cN-68xrliMXVH3m6vZdRKhbtYqCozjbmEH8nPwBFtlri15vhR5lWTT_x3VsZOHhuhbAFzyshIcYAxNDVkUssPWpDag26fRcPsIJ-Oozvp9ld1uOnu9BNSOCWF4DXUTRBfUx55pl1ihwgHrFt36eHdtQ90vJXflsJvLoHuKf4LKt0dOpsPYeJp74V1X06DFlVqL9JGAS3iSLZ_tK_MpZheJqIr5iPl4qWc4k6gSbeomXR1opKqWmbje5JiZmw';
        $jws = new JOSE_JWS($this->plain_jwt);
        $jws = $jws->sign($this->rsa_keys['private'], 'RS512');
        $this->assertEquals($expected, $jws->toString());
    }

    function testSignPS256() {
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiJ9.eyJmb28iOiJiYXIifQ.jukVdy99ZcyKvnkeeZ96c9J8c8FhyAO1ElSn6qHYzxTOjUXWxaaOU_5PZBA-_Bl7SUiLUGS4zv_C2IuH6ZN70MO2omWTcCV544Z2ZesMGsm5ll3kdPeaqtaj1IafDujDRmAJHpUoH2F3GXRAcSmVtj8c9VwJocVdeS-L43wa7uaymT330GRyKajWh8huwMZdgSVJemxct4Y-N2saDvLiVDQwjDWjxNP_eaAh-VFf6sIsK-BRcSRJr-GhwqGcpsvkE7OGbissYlB0fvl6MgxP_fic8ka84SQzX7WcM_zuEgI_J6O4CGPG21lQhJp-Fmme_a7RVDmu0F2kg3cGk81nYA';
        $jws = new JOSE_JWS($this->plain_jwt);
        $jws = $jws->sign($this->rsa_keys['private'], 'PS256');
        # NOTE: RSA-PSS generates different signature each time
        $expected_segments = explode('.', $expected);
        $given_segments = explode('.', $jws->toString());
        $this->assertEquals($expected_segments[0], $given_segments[0]);
        $this->assertEquals($expected_segments[1], $given_segments[1]);
    }

    function testSignPS384() {
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzM4NCJ9.eyJmb28iOiJiYXIifQ.LLtxr-Np3CrTn5mjwftJL6kiPQ4tTnD2C045Vde3g6Y2OX3dYz8YOLINBaC3eM2A9n6YrB9upkGi4lB2zRUCWbdt5-qf9z8M59Wq-EcJdfmhy7bGhc3Kjejpn5IXON3NdnZo8rbRqUntuVyL-aBbQrN42-5wHLGlenwF4nv_GSAj7HYYrwsCEdPxU-cc_hF3_llAxuROARLDJmKGmuKUnZyYvKg2nxwOM2TAWpeRYdVwXv9d5QD61ieS0sxuK8pEiShENRFgRjMoZDAf3TXNO84HAIURuynNH_fD6o-ltmjcfiCzR67Jf0F863vpVzOGkzAs2HxiI2I5XmP_rXAgEg';
        $jws = new JOSE_JWS($this->plain_jwt);
        $jws = $jws->sign($this->rsa_keys['private'], 'PS384');
        # NOTE: RSA-PSS generates different signature each time
        $expected_segments = explode('.', $expected);
        $given_segments = explode('.', $jws->toString());
        $this->assertEquals($expected_segments[0], $given_segments[0]);
        $this->assertEquals($expected_segments[1], $given_segments[1]);
    }

    function testSignPS512() {
        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzUxMiJ9.eyJmb28iOiJiYXIifQ.UA7Wl5HKZEgrZgvVBC3f-hAvs9qdStGAXLz_FIbK38wScksxcZXdFVvnlwJTJ4YmMA64gmRUKz1-jx2XaodcFknAEvUsNtxJqMLgl19ZIOHo7Mb_9JeL1rjVu2IBwgmbpMaUap14QZFKvEeXVm0IV4a8ue8fjAtZKWCslRkCPOWoVqZB5UwnN4ErYEN4UzaxRpOqu161NobaOASgXFe_puwvct5pcHrxVcevziT-N4uwyiz1zpBoGxV17CU-gAq1lxIIUVKJKQPqspjvjYY0aq0PwhlLT1-da4rrqvwKV0cRA0ODSaLXu7y_axxDPGzevtIaBvdYpT5MBAN9Dxy8fw';
        $jws = new JOSE_JWS($this->plain_jwt);
        $jws = $jws->sign($this->rsa_keys['private'], 'PS512');
        # NOTE: RSA-PSS generates different signature each time
        $expected_segments = explode('.', $expected);
        $given_segments = explode('.', $jws->toString());
        $this->assertEquals($expected_segments[0], $given_segments[0]);
        $this->assertEquals($expected_segments[1], $given_segments[1]);
    }

    function testSignRS256WithInvalidPrivateKey() {
        $jws = new JOSE_JWS($this->plain_jwt);
        $this->setExpectedException('JOSE_Exception');
        $jws = $jws->sign('invalid pem', 'RS256');
    }

    function testSignES256() {
        $jws = new JOSE_JWS($this->plain_jwt);
        $this->setExpectedException('JOSE_Exception_UnexpectedAlgorithm');
        $jws = $jws->sign('es key should be here', 'ES256');
    }

    function testSignUnknowAlg() {
        $jws = new JOSE_JWS($this->plain_jwt);
        $this->setExpectedException('JOSE_Exception_UnexpectedAlgorithm');
        $jws = $jws->sign('secret', 'AES256');
    }

    function testVerifyHS256() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.jBKXM6zRu0nP2tYgNTgFxRDwKoiEbNl1P6GyXEHIwEw';
        $jwt = JOSE_JWT::decode($input);
        $jws = new JOSE_JWS($jwt);
        $this->assertInstanceOf('JOSE_JWS', $jws->verify('shared-secret'));
    }

    function testVerifyHS384() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJmb28iOiJiYXIifQ.EoHJwaBtAB7OQzhInUDK5QBrKqhYX8OodiAgusI3fOJsueTm6aOpKvngGj3afGQo';
        $jwt = JOSE_JWT::decode($input);
        $jws = new JOSE_JWS($jwt);
        $this->assertInstanceOf('JOSE_JWS', $jws->verify('shared-secret'));
    }

    function testVerifyHS512() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJmb28iOiJiYXIifQ.eLwaujbDB1c19eOGpxwMksVHCkE5XLA4eps80ZDPAE8_FdQOMQvC6lF0mtAHljAai9XHEDWMXUz1NCeovs8ZVQ';
        $jwt = JOSE_JWT::decode($input);
        $jws = new JOSE_JWS($jwt);
        $this->assertInstanceOf('JOSE_JWS', $jws->verify('shared-secret'));
    }

    function testVerifyRS256() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.GzzxRgDHjgBjDkbMsKaFhWnQ43xKlh8T7Ce34b9ye4afuIfE2EglIlK1itGRx1PtH7UOcwtXVWElJ0lHuuTl6hCUL5SDOMJxiPfr5SkTZFWy2SlSYNtdRfra6NPeEa3-a_15dUYv41QY14TCl5HaP7jeMLeqcTlMcjra9fDPMWUciSyWay6025wUiSQBmWW-19GNZQnRHxXNX3lCVMEQMASYT-6QqBvoiJ6vezIt08RghgGdMH1iGY_Gnb7ISuA-lvKk6fcQvQ3MN5Cx0CeqXlXP8NQQF0OwkUgTjNGsKmCG6jKlLZLeXJb72KVK1yR-6jp7OQqqzrovIP7lp-FwIw';
        $jwt = JOSE_JWT::decode($input);
        $jws = new JOSE_JWS($jwt);
        $this->assertInstanceOf('JOSE_JWS', $jws->verify($this->rsa_keys['public']));
    }

    function testVerifyRS384() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJmb28iOiJiYXIifQ.Odg4nlRTnH1mI1JQEJEQCB1mmqDPFn-Gf5Te8IfLzu7sGDrvZdvGe6HutsDO3mXi7FLtQcI2i0KEQxj8fDUV4vfR1fbfyGQaz02qnt3HKEOgRGwFH1l57ayGChZftXhSCpbt9sMwTg1lsZ_egThQWG0ZErkibmXIt5ZxNwITaXX4oU3k12eH492IsScz_tIaf9NCwIQlAPodiVQL7WMQgej0o4LuZKk6ZgBsDJz_Ms2_iONxzGPWOT76iLOwYT8QaEsLX6d8_WsZ4wnfaxHVlg-zNM0Lhisi_F0_tFeueDOZPJnQp_InV7iYzP4adWOItzG_Qz_-EaNGTz4RJtxqAQ';
        $jwt = JOSE_JWT::decode($input);
        $jws = new JOSE_JWS($jwt);
        $this->assertInstanceOf('JOSE_JWS', $jws->verify($this->rsa_keys['public']));
    }

    function testVerifyRS512() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJmb28iOiJiYXIifQ.uQAVgGt1oy8FlMaAx8UDnVwzuDuJsqYIDHm8cKRKqLqcZ0zUmQHgfonBA09r5CiqG5EGTaX58G6_hAFAmf-aRtJrm_cN-68xrliMXVH3m6vZdRKhbtYqCozjbmEH8nPwBFtlri15vhR5lWTT_x3VsZOHhuhbAFzyshIcYAxNDVkUssPWpDag26fRcPsIJ-Oozvp9ld1uOnu9BNSOCWF4DXUTRBfUx55pl1ihwgHrFt36eHdtQ90vJXflsJvLoHuKf4LKt0dOpsPYeJp74V1X06DFlVqL9JGAS3iSLZ_tK_MpZheJqIr5iPl4qWc4k6gSbeomXR1opKqWmbje5JiZmw';
        $jwt = JOSE_JWT::decode($input);
        $jws = new JOSE_JWS($jwt);
        $this->assertInstanceOf('JOSE_JWS', $jws->verify($this->rsa_keys['public']));
    }

    function testVerifyPS256() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiJ9.eyJmb28iOiJiYXIifQ.jukVdy99ZcyKvnkeeZ96c9J8c8FhyAO1ElSn6qHYzxTOjUXWxaaOU_5PZBA-_Bl7SUiLUGS4zv_C2IuH6ZN70MO2omWTcCV544Z2ZesMGsm5ll3kdPeaqtaj1IafDujDRmAJHpUoH2F3GXRAcSmVtj8c9VwJocVdeS-L43wa7uaymT330GRyKajWh8huwMZdgSVJemxct4Y-N2saDvLiVDQwjDWjxNP_eaAh-VFf6sIsK-BRcSRJr-GhwqGcpsvkE7OGbissYlB0fvl6MgxP_fic8ka84SQzX7WcM_zuEgI_J6O4CGPG21lQhJp-Fmme_a7RVDmu0F2kg3cGk81nYA';
        $jwt = JOSE_JWT::decode($input);
        $jws = new JOSE_JWS($jwt);
        $this->assertInstanceOf('JOSE_JWS', $jws->verify($this->rsa_keys['public']));
    }

    function testVerifyPS384() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzM4NCJ9.eyJmb28iOiJiYXIifQ.LLtxr-Np3CrTn5mjwftJL6kiPQ4tTnD2C045Vde3g6Y2OX3dYz8YOLINBaC3eM2A9n6YrB9upkGi4lB2zRUCWbdt5-qf9z8M59Wq-EcJdfmhy7bGhc3Kjejpn5IXON3NdnZo8rbRqUntuVyL-aBbQrN42-5wHLGlenwF4nv_GSAj7HYYrwsCEdPxU-cc_hF3_llAxuROARLDJmKGmuKUnZyYvKg2nxwOM2TAWpeRYdVwXv9d5QD61ieS0sxuK8pEiShENRFgRjMoZDAf3TXNO84HAIURuynNH_fD6o-ltmjcfiCzR67Jf0F863vpVzOGkzAs2HxiI2I5XmP_rXAgEg';
        $jwt = JOSE_JWT::decode($input);
        $jws = new JOSE_JWS($jwt);
        $this->assertInstanceOf('JOSE_JWS', $jws->verify($this->rsa_keys['public']));
    }

    function testVerifyPS512() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzUxMiJ9.eyJmb28iOiJiYXIifQ.UA7Wl5HKZEgrZgvVBC3f-hAvs9qdStGAXLz_FIbK38wScksxcZXdFVvnlwJTJ4YmMA64gmRUKz1-jx2XaodcFknAEvUsNtxJqMLgl19ZIOHo7Mb_9JeL1rjVu2IBwgmbpMaUap14QZFKvEeXVm0IV4a8ue8fjAtZKWCslRkCPOWoVqZB5UwnN4ErYEN4UzaxRpOqu161NobaOASgXFe_puwvct5pcHrxVcevziT-N4uwyiz1zpBoGxV17CU-gAq1lxIIUVKJKQPqspjvjYY0aq0PwhlLT1-da4rrqvwKV0cRA0ODSaLXu7y_axxDPGzevtIaBvdYpT5MBAN9Dxy8fw';
        $jwt = JOSE_JWT::decode($input);
        $jws = new JOSE_JWS($jwt);
        $this->assertInstanceOf('JOSE_JWS', $jws->verify($this->rsa_keys['public']));
    }

    function testVerifyES256() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.MEQCIDh9M3Id8pPd9fp6kgtirYpAirRCU-H0IbaeruLOYWc_AiBhbsswHCIlY5yqWDsOU_sy3lMnyXlrYoQLcejPxL-nDg';
        $jwt = JOSE_JWT::decode($input);
        $jws = new JOSE_JWS($jwt);
        $this->setExpectedException('JOSE_Exception_UnexpectedAlgorithm');
        $jws = $jws->verify('es key should be here');
    }

    function testVerifyUnknowAlg() {
        $input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJ1bmtub3duIn0.eyJmb28iOiJiYXIifQ.';
        $jwt = JOSE_JWT::decode($input);
        $jws = new JOSE_JWS($jwt);
        $this->setExpectedException('JOSE_Exception_UnexpectedAlgorithm');
        $jws = $jws->verify('no key works');
    }

    function testVerifyWithGoogleIDToken() {
        $id_token_string = file_get_contents($this->fixture_dir . 'google.jwt');
        $cert_string = file_get_contents($this->fixture_dir . 'google.crt');
        $x509 = new File_X509();
        $x509->loadX509($cert_string);
        $public_key = $x509->getPublicKey()->getPublicKey();
        $jwt = JOSE_JWT::decode($id_token_string);
        $jws = new JOSE_JWS($jwt);
        $this->assertInstanceOf('JOSE_JWS', $jws->verify($public_key));
    }
}