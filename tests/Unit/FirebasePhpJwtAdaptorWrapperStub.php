<?php
/******************************************************************************
 * Copyright 2021 Alexandr Orosciuc <alex.orosciuc@gmail.com>                 *
 *                                                                            *
 * For the full copyright and license information, please view the LICENSE    *
 * file that was distributed with this source code.                           *
 ******************************************************************************/

use Okta\CacheAware\FirebasePhpJwtAdaptorWrapper;
use Firebase\JWT\SignatureInvalidException;
use Okta\JwtVerifier\Jwt;

class FirebasePhpJwtAdaptorWrapperStub extends FirebasePhpJwtAdaptorWrapper
{
    private $alreadyCalled = false;

    /**
     * @param $jwt
     * @param $keys
     *
     * @return Jwt
     */
    public function decode($jwt, $keys): Jwt
    {
        if (!$this->alreadyCalled) {
            $this->alreadyCalled = true;
            throw new SignatureInvalidException();
        }

        $jwt = new Jwt($jwt, []);
        return $jwt;
    }

    public function parseKeySet($source)
    {
        $pemKey = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDLXp6PkCtbpV+P1gwFQWH6Ez0U\n83uEmS8IGnpeI8Fk8rY/vHOZzZZaxRCw+loyc342qCDIQheMOCNm5Fkevz06q757\n/oooiLR3yryYGKiKG1IZIiplmtsC95oKrzUSKk60wuI1mbgpMUP5LKi/Tvxes5Pm\nkUtXfimz2qgkeUcPpQIDAQAB\n-----END PUBLIC KEY-----\n";
        $openSslKey = openssl_pkey_get_public($pemKey);
        return ['kid' => $openSslKey];
    }
}
