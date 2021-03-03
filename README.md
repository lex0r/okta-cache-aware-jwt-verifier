# Cached JWKS for Okta JWT Verifier

This library is an extension for [Okta JWT Verifier library](https://github.com/okta/okta-jwt-verifier-php) that adds one important feature: caching of JWKS for JWT token verification.

It relies on [Symfony's Cache component](https://github.com/symfony/cache) for caching the JWKS.

## Installation
Assuming you have already installed the [Okta's library](https://github.com/okta/okta-jwt-verifier-php)
you will have to modify your composer.json to include this library from the Github repository:

```bash
{
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/lex0r/okta-cache-aware-jwt-verifier"
        }
    ]
}
```

and then run

```bash
composer require lex0r/okta-cache-aware-jwt-verifier:dev-main
```

## Usage
The usage is similar to the original Okta library. Please refer to their README for more details.

The main difference is using a cache adaptor and passing it to an instance of `FirebasePhpJwtAdaptor`.

```php
<?php
require_once("/vendor/autoload.php");

$jwt = 'someJwt';
$cache = new \Symfony\Contracts\Cache\FilesystemAdapter('myApp'); // or any other adapter of your choice
$adaptor = new \Okta\CacheAware\FirebasePhpJwtAdaptor($cache);

$jwtVerifier = (new \Okta\CacheAware\JwtVerifierBuilder())
    ->setDiscovery(new \Okta\JwtVerifier\Discovery\Oauth)
    ->setAdaptor($adaptor)
    ->setAudience('someAudience')
    ->setClientId('{oAuthClientId}')
    ->setIssuer('https://myAuthorisationServer.com/')
    ->build();

$jwt = $jwtVerifier->verify($jwt);
```
