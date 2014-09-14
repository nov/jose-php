# JOSE

PHP JOSE (Javascript Object Signing and Encryption) Implementation

[![Build Status](https://travis-ci.org/nov/jose-php.png?branch=master)](https://travis-ci.org/nov/jose-php)

## Requirements

phpseclib is required.
http://phpseclib.sourceforge.net

## Example

### JWT

#### Encoding

```php
$jwt = new JOSE_JWT(array(
    'foo' => 'bar'
));
$jwt->toString();
```

#### Decoding
```php
$jwt_string = 'eyJ...';
$jwt = JOSE_JWT::decode($jwt_string);
```
### JWS

#### Signing
```php
$private_key = "-----BEGIN RSA PRIVATE KEY-----\n....";
$jwt = new JOSE_JWT(array(
    'foo' => 'bar'
));
$jws = $jwt->sign($private_key, 'RS256');
```
#### Verification
```php
$public_key = "-----BEGIN RSA PUBLIC KEY-----\n....";
$jwt_string = 'eyJ...';
$jwt = JOSE_JWT::decode($jwt_string);
$jws = new JOSE_JWS($jwt);
$jws->verify($public_key);
```

### JWE

#### Encryption

not supported yet

#### Decryption
```php
$jwt_string = 'eyJ...';
$jwt = JOSE_JWT::decode($jwt_string);
$jwt->decrypt($private_key);
```

### JWK file creation

The JOSE_JWKMaker take the properties below: 
 - $file_rsa_key (string) [REQUIRED], path to the private, public certificat
 - $kid (string), 'kid' string
 - $use (string), 'use' string, most of time 'use' is set with 'sig' or 'enc'
 - $pass_phrase (string), the pass phrase of private certificate

Take a look at [JOSE_JWKMakerTest](test/JOSE/JWKMaker_Test.php) for more exemple.

```php
$jWKMaker = new JOSE_JWKMaker("private_rsa_key", $kid , $use, $passphrase);
$jwkContent = $jWKMaker->makeJwkContent();
```

## Run Test

```bash
git clone git://github.com/gree/jose.git
cd jose
php composer.phar install --dev
./vendor/bin/phpunit -c test/phpunit.xml --tap
```

### JWK
Json Web Key
```php
$jwt = JOSE_JWT::decode($jwt_string);
if (array_key_exists('jku', $jwt->header)) {

    /*get back the content of the jku URL*/
    $jwkSetJsonObject = json_decode(file_get_content($jwt->header['jku']));

    $jwkSet = new \JOSE_JWKSet();
    $jwkSet->setJwksFromJsonObject($jwkSetJsonObject);

    $jws = new \JOSE_JWS($jwt);
    $jws->verify($jwkSet);
}
```


## Copyright

Copyright &copy; 2013 GREE Inc. See LICENSE for details.
