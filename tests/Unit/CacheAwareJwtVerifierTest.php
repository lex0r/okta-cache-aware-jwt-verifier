<?php
/******************************************************************************
 * Copyright 2021 Alexandr Orosciuc <alex.orosciuc@gmail.com>                 *
 * This file incorporates work covered by the following copyright:            *
 *   Copyright 2017 Okta, Inc.                                                *
 *                                                                            *
 * For the full copyright and license information, please view the LICENSE    *
 * file that was distributed with this source code.                           *
 ******************************************************************************/

require __DIR__ . '/FirebasePhpJwtAdaptorWrapperStub.php';

use Okta\CacheAware\FirebasePhpJwtAdaptor;
use Okta\CacheAware\JwtVerifier;
use Okta\CacheAware\FirebasePhpJwtAdaptorWrapper;
use GuzzleHttp\Psr7\Response;
use Http\Mock\Client;
use Okta\JwtVerifier\Discovery\Oauth;
use Okta\JwtVerifier\Jwt;
use Okta\JwtVerifier\Request;

class CacheAwareJwtVerifierTest extends BaseTestCase
{
    /** @test */
    public function it_can_get_issuer_off_object()
    {
        $this->response
            ->method('getBody')
            ->willreturn('{"issuer": "https://my.issuer.com"}');

        $httpClient = new Client;
        $httpClient->addResponse($this->response);
        $request = new Request($httpClient);

        $adaptorWrapper = $this->createConfiguredMock(FirebasePhpJwtAdaptorWrapper::class, [
            'decode' => new Jwt('jwt', ['claims' => 'foobar']),
            'parseKeySet' => ['key1', 'key2'],
        ]);
        $cacheAwareAdaptor = new FirebasePhpJwtAdaptor($this->cacheAdapter, $request, $adaptorWrapper);

        $verifier = new JwtVerifier(
            'https://my.issuer.com',
            new Oauth(),
            $cacheAwareAdaptor
        );

        $this->assertEquals(
            'https://my.issuer.com',
            $verifier->getIssuer(),
            'Does not return issuer correctly'
        );
    }

    /** @test */
    public function it_can_get_discovery_off_object()
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

        $verifier = new JwtVerifier(
            'https://my.issuer.com',
            new Oauth(),
            $cacheAwareAdaptor
        );

        $this->assertInstanceOf(
            Oauth::class,
            $verifier->getDiscovery(),
            'Does not return discovery correctly'
        );
    }

    /** @test */
    public function it_will_get_meta_data_when_called_with_issuer()
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

        $verifier = new JwtVerifier(
            'https://my.issuer.com',
            new Oauth(),
            $cacheAwareAdaptor
        );

        $metaData = $verifier->getMetaData();

        $this->assertEquals(
            'https://example.com',
            $metaData->issuer,
            'Metadata was not accessed.'
        );
    }

    /** @test */
    public function it_will_reload_keys_upon_invalid_signature_exception()
    {
        $this->response
            ->method('getBody')
            ->willreturn('{"issuer": "https://example.com", "jwks_uri": "https://someuri.net"}');

        $httpClient = new Client;
        $httpClient->addResponse($this->response); // 1st metadata call
        $httpClient->addResponse(new Response());  // Key call
        $httpClient->addResponse($this->response); // 2nd metadata call
        $request = new Request($httpClient);

        $adaptorWrapper = new FirebasePhpJwtAdaptorWrapperStub($request);
        $cacheAwareAdaptor = new FirebasePhpJwtAdaptor($this->cacheAdapter, $request, $adaptorWrapper);

        $verifier = new JwtVerifier(
            'https://my.issuer.com',
            new Oauth(),
            $cacheAwareAdaptor,
            ['nonce' => null, 'audience' => null, 'clientId' => null]
        );

        // Not failing after this line is a sign of correct behaviour.
        $verifier->verify('sometoken');

        $this->assertTrue($this->cacheAdapter->hasItem($cacheAwareAdaptor->getKeyCacheKey()));
    }
}
