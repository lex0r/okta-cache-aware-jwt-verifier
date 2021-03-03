<?php
/******************************************************************************
 * Copyright 2021 Alexandr Orosciuc <alex.orosciuc@gmail.com>                 *
 *                                                                            *
 * For the full copyright and license information, please view the LICENSE    *
 * file that was distributed with this source code.                           *
 ******************************************************************************/

namespace Okta\CacheAware;

use Okta\JwtVerifier\Adaptors\FirebasePhpJwt;
use Okta\JwtVerifier\Discovery\DiscoveryMethod;
use Okta\JwtVerifier\Discovery\Oauth;
use Okta\JwtVerifier\Jwt;
use Okta\JwtVerifier\Request;
use Psr\Cache\InvalidArgumentException;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

final class FirebasePhpJwtAdaptor implements AdaptorInterface
{
    /**
     * @var FirebasePhpJwtAdaptorWrapper
     */
    private $adaptorWrapper;

    /**
     * @var CacheInterface
     */
    private $cache;

    /**
     * @var Request
     */
    private $request;

    /**
     * @var string
     */
    private $wellKnown;

    /**
     * @var mixed
     */
    protected $metaData;

    /**
     * CacheAwareFirebasePhpJwtAdaptor constructor.
     *
     * @param CacheInterface                    $cache
     * @param Request|null                      $request
     * @param FirebasePhpJwtAdaptorWrapper|null $firebasePhpJwtAdaptorWrapper
     * @param int                               $leeway
     */
    public function __construct(
        CacheInterface $cache,
        Request $request = null,
        FirebasePhpJwtAdaptorWrapper $firebasePhpJwtAdaptorWrapper = null,
        int $leeway = 120
    ) {
        $this->cache = $cache;
        $this->request = $request ?? new Request;
        $this->adaptorWrapper = $firebasePhpJwtAdaptorWrapper ?? new FirebasePhpJwtAdaptorWrapper($request, $leeway);
    }

    /**
     * @param $jwt
     * @param $keys
     *
     * @return Jwt
     */
    public function decode($jwt, $keys): Jwt
    {
        return $this->adaptorWrapper->decode($jwt, $keys);
    }

    /**
     * @param string|null          $issuer
     * @param DiscoveryMethod|null $discovery
     *
     * @return mixed
     * @throws InvalidArgumentException
     */
    public function getMetadata(string $issuer = null, DiscoveryMethod $discovery = null)
    {
        $discovery = $discovery ?? (new Oauth())->getWellKnown();
        if (!$this->wellKnown && !$issuer) {
            throw new \InvalidArgumentException("Metadata can't be fetched because no issuer was provided");
        }
        $this->wellKnown = $this->wellKnown ?? $issuer . $discovery->getWellKnown();
        $cacheKey = $this->getMetadataCacheKey();

        return $this->cache->get($cacheKey, function (ItemInterface $item) {
            return $this->fetchMetadata();
        });
    }

    /**
     * @param string               $issuer
     * @param DiscoveryMethod|null $discovery
     * @param bool                 $forceReload
     *
     * @return mixed
     * @throws InvalidArgumentException
     */
    public function getKeys(string $issuer, DiscoveryMethod $discovery = null, bool $forceReload = false)
    {
        $discovery = $discovery ? $discovery->getWellKnown() : (new Oauth())->getWellKnown();
        $this->wellKnown = $this->wellKnown ?? $issuer . $discovery;
        $keyCacheKey = $this->getKeyCacheKey();

        if ($forceReload) {
            $metadataCacheKey = $this->getMetadataCacheKey();
            $this->cache->delete($metadataCacheKey);
            $this->cache->delete($keyCacheKey);
        }

        $pemKeys = $this->cache->get($keyCacheKey, function (ItemInterface $item) {
            return array_map(
                function ($openSslKey) {
                    $keyDetails = openssl_pkey_get_details($openSslKey);
                    return $keyDetails['key'];
                },
                $this->fetchKeys()
            );
        });

        return array_map('openssl_get_publickey', $pemKeys);
    }

    /**
     * @return bool
     */
    public static function isPackageAvailable(): bool
    {
        return FirebasePhpJwt::isPackageAvailable();
    }

    /**
     * @return string
     */
    public function getMetadataCacheKey(): string
    {
        return 'jwt_cached_metadata_' . md5($this->wellKnown);
    }

    /**
     * @return string
     */
    public function getKeyCacheKey(): string
    {
        return 'jwt_cached_key_' . md5($this->wellKnown);
    }

    /**
     * @return mixed
     */
    private function fetchMetadata()
    {
        return json_decode(
            $this->request->setUrl($this->wellKnown)->get()->getBody()
        );
    }

    /**
     * @return array
     * @throws InvalidArgumentException
     */
    private function fetchKeys()
    {
        $this->metaData = $this->getMetadata();

        if ($this->metaData->jwks_uri == null) {
            throw new \DomainException("'jwks_uri' attribute not found in {$this->wellKnown}");
        }

        $keys = json_decode($this->request->setUrl($this->metaData->jwks_uri)->get()->getBody()->getContents());

        return $this->adaptorWrapper->parseKeySet($keys);
    }
}
