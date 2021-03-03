<?php
/******************************************************************************
 * Copyright 2021 Alexandr Orosciuc <alex.orosciuc@gmail.com>                 *
 * This file incorporates work covered by the following copyright:            *
 *   Copyright 2017 Okta, Inc.                                                *
 *                                                                            *
 * For the full copyright and license information, please view the LICENSE    *
 * file that was distributed with this source code.                           *
 ******************************************************************************/

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

class BaseTestCase extends TestCase
{
    /**
     * @var MockObject
     */
    protected $response;

    /**
     * @var ArrayAdapter
     */
    protected $cacheAdapter;

    public function setUp(): void
    {
        parent::setUp();

        $this->response = self::createMock('Psr\Http\Message\ResponseInterface');
        $this->cacheAdapter = new ArrayAdapter();
    }
}
