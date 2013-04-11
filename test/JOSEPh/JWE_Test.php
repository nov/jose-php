<?php

class JOSEPh_JWE_Test extends JOSEPh_TestCase {
    var $plain_text;
    var $rsa_keys;

    function setUp() {
        parent::setUp();
        $this->plain_text = 'Hello World';
        $this->rsa_keys = array(
            'public'  => file_get_contents($this->fixture_dir . 'public_key.pem'),
            'private' => file_get_contents($this->fixture_dir . 'private_key.pem')
        );
    }

    function testDecryptRSA15A128GCM() {
        $input = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDK0hTMjU2In0.gOIfTaAkLJYGsK-anmDgxokNit2UqKiraKyExUxM0oj5mw2UngEUGvLK-iztMTiONovqwsMmxOsoZLt_t7paCAx1_3KB1YuCZtBF-0_eH54j0KRdF1Ht8xDaPg0nNmkfSqn19EM-fZVDNBK4Jig-8eF0nbtq1EjL9m6AXV1utIQgM5-3gDtnXkNJ8pYkS22Lga4906smr5IkswdlJEvu81GFV7haFb1Edpyw_Ty0El8KW-p0Udz5FFZD_16qO4FzvSJk73X2l21zXENqUXhiFJDXacBOozpyGL0Rf-idwk9-X3mh8RThutcTelVUOWYdcW-7B8oLaeLEPFYeaLLsjQ.AaxiImKsfoBGoM5s9bp90Q.5KBllDM4n5Po3BhQ8CkpTQ.MNpTRLD3plIxs6JqR6h2ww0D97T5R9oNtE7uplkUcdE';
        $jwe = new JOSEPh_JWE($input);
        $jwe->decrypt($this->rsa_keys['private']);
        $this->fail('should fail');
    }
}