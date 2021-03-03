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

use Bretterer\IsoDurationConverter\DurationParser;
use Okta\JwtVerifier\Discovery\DiscoveryMethod;
use Okta\JwtVerifier\Request;

final class JwtVerifierBuilder
{
    protected $issuer;
    protected $discovery;
    protected $request;
    protected $adaptor;
    protected $audience;
    protected $clientId;
    protected $nonce;
    protected $leeway = 120;

    /**
     * JwtVerifierBuilder constructor.
     *
     * @param Request|null $request
     */
    public function __construct(Request $request = null)
    {
        $this->request = $request;
    }

    /**
     * Sets the issuer URI.
     *
     * @param string $issuer The issuer URI
     *
     * @return JwtVerifierBuilder
     */
    public function setIssuer(string $issuer): self
    {
        $this->issuer = rtrim($issuer, "/");

        return $this;
    }

    /**
     * Set the Discovery class. This class should be an instance of DiscoveryMethod.
     *
     * @param DiscoveryMethod $discoveryMethod The DiscoveryMethod instance.
     *
     * @return JwtVerifierBuilder
     */
    public function setDiscovery(DiscoveryMethod $discoveryMethod): self
    {
        $this->discovery = $discoveryMethod;

        return $this;
    }

    /**
     * Set the Adaptor class. This class should be an interface of Adaptor.
     *
     * @param AdaptorInterface $adaptor The adaptor of the JWT library you are using.
     *
     * @return JwtVerifierBuilder
     */
    public function setAdaptor(AdaptorInterface $adaptor): self
    {
        $this->adaptor = $adaptor;

        return $this;
    }

    /**
     * @param $audience
     *
     * @return $this
     */
    public function setAudience($audience): self
    {
        $this->audience = $audience;

        return $this;
    }

    /**
     * @param $clientId
     *
     * @return $this
     */
    public function setClientId($clientId): self
    {
        $this->clientId = $clientId;

        return $this;
    }

    /**
     * @param $nonce
     *
     * @return $this
     */
    public function setNonce($nonce): self
    {
        $this->nonce = $nonce;

        return $this;
    }

    /**
     * Set the leeway using ISO_8601 Duration string. ie: PT2M
     *
     * @param string $leeway ISO_8601 Duration format. Default: PT2M
     * @return self
     * @throws \InvalidArgumentException
     */
    public function setLeeway(string $leeway = "PT2M"): self
    {
        if (strstr($leeway, "P")) {
            throw new \InvalidArgumentException("It appears that the leeway provided is not in ISO_8601 Duration Format.  Please provide a duration in the format of `PT(n)S`");
        }

        $leeway = (new DurationParser)->parse($leeway);
        $this->leeway = $leeway;

        return $this;
    }

    /**
     * Build and return the JwtVerifier.
     *
     * @return JwtVerifier
     */
    public function build(): JwtVerifier
    {
        $this->validateIssuer($this->issuer);

        $this->validateClientId($this->clientId);

        return new JwtVerifier(
            $this->issuer,
            $this->discovery,
            $this->adaptor,
            [
                'nonce' => $this->nonce,
                'audience' => $this->audience,
                'clientId' => $this->clientId
            ]
        );
    }

    /**
     * Validate the issuer
     *
     * @param string $issuer
     * @throws \InvalidArgumentException
     * @return void
     */
    private function validateIssuer($issuer): void {
        if (null === $issuer || "" == $issuer) {
            throw new \InvalidArgumentException("Your Issuer is missing. You can find your issuer from your authorization server settings in the Okta Developer Console. Find out more information aobut Authorization Servers at https://developer.okta.com/docs/guides/customize-authz-server/overview/");
        }

        if (strstr($issuer, "https://") == false) {
            throw new \InvalidArgumentException("Your Issuer must start with https. Current value: {$issuer}. You can copy your issuer from your authorization server settings in the Okta Developer Console. Find out more information aobut Authorization Servers at https://developer.okta.com/docs/guides/customize-authz-server/overview/");
        }

        if (strstr($issuer, "{yourOktaDomain}") != false) {
            throw new \InvalidArgumentException("Replace {yourOktaDomain} with your Okta domain. You can copy your domain from the Okta Developer Console. Follow these instructions to find it: https://bit.ly/finding-okta-domain");
        }
    }

    /**
     * Validate the client id
     *
     * @param string $cid
     * @throws \InvalidArgumentException
     * @return void
     */
    private function validateClientId($cid): void {
        if (null === $cid || "" == $cid) {
            throw new \InvalidArgumentException("Your client ID is missing. You can copy it from the Okta Developer Console in the details for the Application you created. Follow these instructions to find it: https://bit.ly/finding-okta-app-credentials");
        }

        if (strstr($cid, "{clientId}") != false) {
            throw new \InvalidArgumentException("Replace {clientId} with the client ID of your Application. You can copy it from the Okta Developer Console in the details for the Application you created. Follow these instructions to find it: https://bit.ly/finding-okta-app-credentials");
        }
    }
}
