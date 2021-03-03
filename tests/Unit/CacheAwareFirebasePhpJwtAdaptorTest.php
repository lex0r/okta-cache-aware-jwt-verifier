<?php
/******************************************************************************
 * Copyright 2021 Alexandr Orosciuc <alex.orosciuc@gmail.com>                 *
 *                                                                            *
 * For the full copyright and license information, please view the LICENSE    *
 * file that was distributed with this source code.                           *
 ******************************************************************************/

use Okta\CacheAware\FirebasePhpJwtAdaptor;
use Okta\CacheAware\FirebasePhpJwtAdaptorWrapper;
use Http\Mock\Client;
use Okta\JwtVerifier\Jwt;
use Okta\JwtVerifier\Request;

class CacheAwareFirebasePhpJwtAdaptorTest extends BaseTestCase
{
    /**
     * @test
     */
    public function it_will_throw_exception_when_getting_metadata_without_parameters_before_keys()
    {
        $this->response
            ->method('getBody')
            ->willreturn('{"issuer": "https://example.com"}');
        $httpClient = new Client;
        $httpClient->addResponse($this->response);
        $request = new Request($httpClient);

        $adaptorWrapper = $this->createConfiguredMock(FirebasePhpJwtAdaptorWrapper::class, [
            'decode' => new Jwt('jwt', ['claims' => 'foobar']),
            'parseKeySet' => ['key1', 'key2'],
        ]);
        $cacheAwareAdaptor = new FirebasePhpJwtAdaptor($this->cacheAdapter, $request, $adaptorWrapper);

        $this->expectException(\InvalidArgumentException::class);
        $cacheAwareAdaptor->getMetadata();
    }

    /**
     * @test
     */
    public function it_will_return_keys_when_calling_get_keys_with_cache_reload()
    {
        $pemKey = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDLXp6PkCtbpV+P1gwFQWH6Ez0U\n83uEmS8IGnpeI8Fk8rY/vHOZzZZaxRCw+loyc342qCDIQheMOCNm5Fkevz06q757\n/oooiLR3yryYGKiKG1IZIiplmtsC95oKrzUSKk60wuI1mbgpMUP5LKi/Tvxes5Pm\nkUtXfimz2qgkeUcPpQIDAQAB\n-----END PUBLIC KEY-----\n";
        $openSslKey = openssl_pkey_get_public($pemKey);
        $openSslKeys = ['kid' => $openSslKey];
        $expectedKeys = ['kid' => $pemKey];

        $this->response
            ->method('getBody')
            ->willreturn('{"issuer": "https://example.com", "jwks_uri": "https://someuri.net"}');
        $httpClient = new Client;
        $httpClient->addResponse($this->response);
        $request = new Request($httpClient);

        $adaptorWrapper = $this->createConfiguredMock(FirebasePhpJwtAdaptorWrapper::class, [
            'decode' => new Jwt('jwt', ['claims' => 'foobar']),
            'parseKeySet' => $openSslKeys,
        ]);
        $cacheAwareAdaptor = new FirebasePhpJwtAdaptor($this->cacheAdapter, $request, $adaptorWrapper);

        $keys = $cacheAwareAdaptor->getKeys('https://example.com', null, true);
        $actualKeys = array_map(
            function ($openSslKey) {
                $keyDetails = openssl_pkey_get_details($openSslKey);
                return $keyDetails['key'];
            },
            $keys
        );

        $this->assertEquals($expectedKeys, $actualKeys);
        $this->assertTrue($this->cacheAdapter->hasItem($cacheAwareAdaptor->getKeyCacheKey()));
    }
}
