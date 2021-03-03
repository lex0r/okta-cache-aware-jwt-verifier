<?php
/******************************************************************************
 * Copyright 2021 Alexandr Orosciuc <alex.orosciuc@gmail.com>                 *
 *                                                                            *
 * For the full copyright and license information, please view the LICENSE    *
 * file that was distributed with this source code.                           *
 ******************************************************************************/

namespace Okta\CacheAware;

use Okta\JwtVerifier\Discovery\DiscoveryMethod;
use Okta\JwtVerifier\Jwt;

interface AdaptorInterface
{
    public function getKeys(string $issuer, DiscoveryMethod $discovery);
    public function getMetadata(string $issuer, DiscoveryMethod $discovery);
    public function decode($jwt, $keys): Jwt;
    public static function isPackageAvailable();
}
