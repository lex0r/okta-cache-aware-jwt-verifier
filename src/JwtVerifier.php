<?php
/******************************************************************************
 * Copyright 2021 Alexandr Orosciuc <alex.orosciuc@gmail.com>                 *
 * This file incorporates work covered by the following copyright:            *
 *   Copyright 2017 Okta, Inc.                                                *
 *                                                                            *
 * For the full copyright and license information, please view the LICENSE    *
 * file that was distributed with this source code.                           *
 ******************************************************************************/

namespace Okta\CacheAware;

use Firebase\JWT\SignatureInvalidException;
use Okta\JwtVerifier\Discovery\DiscoveryMethod;
use Okta\JwtVerifier\Discovery\Oauth;
use Okta\JwtVerifier\Jwt;
use Psr\Cache\InvalidArgumentException;

final class JwtVerifier
{
    /**
     * @var string
     */
    private $issuer;

    /**
     * @var DiscoveryMethod
     */
    private $discovery;

    /**
     * @var array
     */
    protected $claimsToValidate;

    /**
     * @var FirebasePhpJwtAdaptor
     */
    private $adaptor;

    /**
     * @var bool
     */
    private $keyReloadAttempted;

    /**
     * CacheAwareJwtVerifier constructor.
     *
     * @param string                               $issuer
     * @param DiscoveryMethod|null                 $discovery
     * @param FirebasePhpJwtAdaptor|null $adaptor
     * @param array                                $claimsToValidate
     */
    public function __construct(
        string $issuer,
        DiscoveryMethod $discovery = null,
        FirebasePhpJwtAdaptor $adaptor = null,
        array $claimsToValidate = []
    ) {
        $this->issuer = $issuer;
        $this->discovery = $discovery ?: new Oauth;
        $this->adaptor = $adaptor;
        $this->claimsToValidate = $claimsToValidate;
    }

    /**
     * @param      $jwt
     * @param bool $reloadKeys
     *
     * @return Jwt
     * @throws InvalidArgumentException
     */
    public function verify($jwt, $reloadKeys = false): Jwt
    {
        try {
            $keys = $this->adaptor->getKeys($this->issuer, $this->discovery, $reloadKeys);
            $decoded = $this->adaptor->decode($jwt, $keys);
            $this->validateClaims($decoded->getClaims());
        }
        catch (SignatureInvalidException $e) {
            if ($this->keyReloadAttempted) {
                throw $e;
            }
            $this->keyReloadAttempted = true;
            return $this->verify($jwt, true);
        }

        return $decoded;
    }

    /**
     * @return string
     */
    public function getIssuer()
    {
        return $this->issuer;
    }

    /**
     * @return DiscoveryMethod|Oauth
     */
    public function getDiscovery()
    {
        return $this->discovery;
    }

    /**
     * @return mixed
     * @throws InvalidArgumentException
     */
    public function getMetaData()
    {
        return $this->adaptor->getMetadata($this->issuer, $this->discovery);
    }

    /**
     * @param array $claims
     *
     * @throws \Exception
     */
    protected function validateClaims(array $claims)
    {
        $this->validateNonce($claims);
        $this->validateAudience($claims);
        $this->validateClientId($claims);
    }

    /**
     * @param $claims
     *
     * @return false
     * @throws \Exception
     */
    protected function validateNonce($claims)
    {
        if (!isset($claims['nonce']) && $this->claimsToValidate['nonce'] == null) {
            return false;
        }

        if ($claims['nonce'] != $this->claimsToValidate['nonce']) {
            throw new \Exception('Nonce does not match what is expected. Make sure to provide the nonce with
            `setNonce()` from the JwtVerifierBuilder.');
        }
    }

    /**
     * @param $claims
     *
     * @return false
     * @throws \Exception
     */
    protected function validateAudience($claims)
    {
        if (!isset($claims['aud']) && $this->claimsToValidate['audience'] == null) {
            return false;
        }

        if ($claims['aud'] != $this->claimsToValidate['audience']) {
            throw new \Exception('Audience does not match what is expected. Make sure to provide the audience with
            `setAudience()` from the JwtVerifierBuilder.');
        }
    }

    /**
     * @param $claims
     *
     * @return false
     * @throws \Exception
     */
    protected function validateClientId($claims)
    {
        if (!isset($claims['cid']) && $this->claimsToValidate['clientId'] == null) {
            return false;
        }

        if ($claims['cid'] != $this->claimsToValidate['clientId']) {
            throw new \Exception('ClientId does not match what is expected. Make sure to provide the client id with
            `setClientId()` from the JwtVerifierBuilder.');
        }
    }
}
