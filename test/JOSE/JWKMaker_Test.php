<?php


/**
 * @group JWKMaker
 */
class JOSE_JWKMakerTest extends JOSE_TestCase {
    
    public function setUp() {
        parent::setUp();
    }
    
    /**
     * @dataProvider dataproviderValidJwkContent
     */
    public function testShouldGenerateValidJWKContentWithPrivateKey($file, $n, $e, $kty, $kid = null, $use = null, $passphrase = null)
    {
        
        $jWKMaker = new JOSE_JWKMaker( __DIR__ . '/../fixtures/' . $file, $kid , $use, $passphrase);
        
        $res = $jWKMaker->makeJwkContent();
        
        $jsonD = json_decode($res, true);

        foreach ($jsonD['keys'][0] as $key => $value) {
            
            $this->assertEquals($$key, $value);
            
        }      
        
    }
    
    public function dataproviderValidJwkContent()
    {
        $n = "sf7a5OoJ0FqcdpHZWLUP5anFlnIJcUhcysSC8utCAiYE6RrV1iSZYhD9eVr14Km8y64B6oPyV9SkSl0D1FWgRU4GAFAFH7mAAljff_tKQA5wRC0dO-q0XAR_bqnejwkmPlEKsboHoV-BuKDyoL_UneEo0W_o9oDuasRNMYmqcjM";
        $n1 = "x9vNhcvSrxjsegZAAo4OEuoZOV_oxINEeWneJYczS80_bQ1J6lSSJ81qecxXAzCLPlvsFoP4eeUNXSt_G7hP7SAM479N-kY_MzbihJ5LRY9sRzLbQTMeqsmDAmmQe4y3Ke3bvd70r8VOmo5pqM3IPLGwBkTRTQmyRsDQArilg6WtxDUgy5ol2STHFA8E1iCReh9bck8ZaLxzVhYRXZ0nuOKWGRMppocPlp55HVohOItUZh7uSCchLcVAZuhTTNaDLtLIJ6G0yNJvfEieJUhA8wGBoPhD3LMQwQMxTMerpjZhP_qjm6GgeWpKf-iVil86_PSy_z0Vw06_rD0sfXPtlQ";
        $n2 = "61BjmfXGEvWmegnBGSuS-rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBSEVCgJjtHAGZIm5GL_KA86KDp_CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7noLBBq1N0bWi1e2i-83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0vTl25XucMcG_ALE_KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7-Bs3h5Ramxh7XjBOXeulmCpGSynXNcpZ_06-vofGi_2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26ZQ";
        $n3 = 'vzHqFNIs9sdtPlTqk8vWmNUEi3ZWhyrRhRoZVVgeGhX6gA28MXK2dPb7iskKtHvUYbIpcW-Iad7sxlvxumEuw_RC7INvK_m0vQE1KMRBUz0XLkooYyxdfcDhZOS04RjuMn3ZfJb-XkmQRYbynf2nvYAIss0f99sD7Duq37n9i5s3BnQjKjC4RMzAvswHNRzeRuGeGBUEbaj6BhTPtPmFuF2nAwy2nXK4AZAbtgaP9FrqTbdkQ82WnPebtlqCMo3Sfge97GhEkjBfuaXnBfkb3rH8Lat8peswMiBLIQJ7j_t_cqv01tO_J_dknJFg6nEzFSjjB3rU4l0QAf5KH4V1QQ';
        $e = "AQAB";
        $kty = "RSA";
        
        return array(
            array("file" => "google.crt", "n" => $n, "e" => $e, "kty" => $kty),
            array("file" => "google.crt", "n" => $n, "e" => $e, "kty" => $kty),
            array("file" => "google.crt", "n" => $n, "e" => $e, "kty" => $kty, "kid" => "aKid"),
            array("file" => "google.crt", "n" => $n, "e" => $e, "kty" => $kty, "kid" => "aKid", "use" => "aUse"),
            array("file" => "google.crt", "n" => $n, "e" => $e, "kty" => $kty, "kid" => null, "use" => "aUse"),
            array("file" => "private_key.pem", "n" => $n1, "e" => $e, "kty" => $kty),
            array("file" => "private_key.pem", "n" => $n1, "e" => $e, "kty" => $kty, "kid" => "aKid"),
            array("file" => "private_key.pem", "n" => $n1, "e" => $e, "kty" => $kty, "kid" => "aKid", "use" => "aUse"),
            array("file" => "private_key.pem", "n" => $n1, "e" => $e, "kty" => $kty, "kid" => null, "use" => "aUse"),
            array("file" => "public_key_type_2", "n" => $n2, "e" => $e, "kty" => $kty),
            array("file" => "public_key_type_2", "n" => $n2, "e" => $e, "kty" => $kty, "kid" => "aKid"),
            array("file" => "public_key_type_2", "n" => $n2, "e" => $e, "kty" => $kty, "kid" => "aKid", "use" => "aUse"),
            array("file" => "public_key_type_2", "n" => $n2, "e" => $e, "kty" => $kty, "kid" => null, "use" => "aUse"),
            array("file" => "private_key_with_pass_phrase", "n" => $n3, "e" => $e, "kty" => $kty, "kid" => null, "use" => null, "passphrase" => "private_key_with_pass_phrase")
        );
    }
    
    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage the file /etc/null/bad-file is a file
     */
    public function testSouldFailAtLoadingCert()
    {
        $jWKMaker = new JOSE_JWKMaker( '/etc/null/bad-file' );
        
        $jWKMaker->makeJwkContent();
    }
    
    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage test/JOSE/../fixtures/google.jwt is not a valid certificate
     */
    public function testSouldFailAtLoadingWrongCert()
    {
        $jWKMaker = new JOSE_JWKMaker( __DIR__ . '/../fixtures/google.jwt');
        
        $jWKMaker->makeJwkContent();
    }
    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage failed to load key
     */
    public function testShouldFailWithFalsePassPhrase()
    {
        $jWKMaker = new JOSE_JWKMaker( __DIR__ . '/../fixtures/private_key_with_pass_phrase', null, null, 'dumb');
        
        $res = $jWKMaker->makeJwkContent();
    }

}