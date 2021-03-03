<?php
/******************************************************************************
 * Copyright 2021 Alexandr Orosciuc <alex.orosciuc@gmail.com>                 *
 *                                                                            *
 * For the full copyright and license information, please view the LICENSE    *
 * file that was distributed with this source code.                           *
 ******************************************************************************/

namespace Okta\CacheAware;

use Okta\JwtVerifier\Adaptors\FirebasePhpJwt;
use Okta\JwtVerifier\Jwt;
use Okta\JwtVerifier\Request;

class FirebasePhpJwtAdaptorWrapper
{
    /**
     * @var FirebasePhpJwt
     */
    private $firebasePhpJwtAdaptor;

    public function __construct(Request $request = null, int $leeway = 120)
    {
        $this->firebasePhpJwtAdaptor = new FirebasePhpJwt($request, $leeway);
    }

    /**
     * @param $jwt
     * @param $keys
     *
     * @return Jwt
     */
    public function decode($jwt, $keys): Jwt
    {
        return $this->firebasePhpJwtAdaptor->decode($jwt, $keys);
    }

    /**
     * @param $source
     *
     * @return array
     */
    public function parseKeySet($source)
    {
        return FirebasePhpJwt::parseKeySet($source);
    }
}
