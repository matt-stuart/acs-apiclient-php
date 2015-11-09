<?php

namespace AcsTest\Unit;

require_once __DIR__ . '/../../src/AcsClient.php';

class AcsClientTest extends \PHPUnit_Framework_TestCase
{
    public function testConstructorDefault()
    {
        $defaults = array(
            'serviceRoot' => 'https://portal2.foreseeresults.com/services/',
            'requestTokenUri' => 'oauth/request_token',
            'accessTokenUri' => 'oauth/access_token',
            'authorizationUri' => 'oauth/user_authorization',
            'loginUri' => 'login',
            'sessionId' => null
        );
        $instance = new \AcsClient();
        $this->assertInstanceOf('AcsClient', $instance);
        foreach ($defaults as $key => $default) {
            $option = $instance->getOption($key);
            $this->assertEquals($default, $option, "'$key'=>'$option' did not match expected default '$default'");
        }
        return $instance;
    }

    public function testConstructorCustom()
    {
        $custom = array(
            'serviceRoot' => 'custom1',
            'requestTokenUri' => 'custom2',
            'accessTokenUri' => 'custom3',
            'authorizationUri' => 'custom4',
            'loginUri' => 'custom5',
            'sessionId' => 'custom6'
        );
        $instance = new \AcsClient($custom);
        foreach ($custom as $key => $value) {
            $option = $instance->getOption($key);
            $this->assertEquals($value, $option, "'$key'=>'$option' did not match expected default '$value'");
        }

        $custom = array(
            'customKey' => 'customValue'
        );
        $instance = new \AcsClient($custom);
        foreach ($custom as $key => $value) {
            $option = $instance->getOption($key);
            $this->assertEquals($value, $option, "'$key'=>'$option' did not match expected default '$value'");
        }
    }

    /**
     * @depends testConstructorDefault
     * @param \AcsClient $instance
     */
    public function testSetOptions($instance)
    {
        // Pass through to method call
        $this->assertInstanceOf(
            'AcsClient',
            $instance->setOptions(array(
            'username' => 'username'
            ))
        );

        $this->assertEmpty($instance->getOption('username'), "Expected the username option to be empty due to special case");
        $this->assertEquals('username', $instance->getUsername(), "Expected username value to be properly set");

        // Direct
        $this->assertInstanceOf(
            'AcsClient',
            $instance->setOptions(array(
                'customOption' => 'customValue'
            ))
        );

        $this->assertEquals('customValue', $instance->getOption('customOption'), "Expected custom option to be set");
    }

    /**
     * @expectedException \InvalidArgumentException
     * @depends testConstructorDefault
     * @param \AcsClient $instance
     */
    public function testMagicCall_Exception($instance)
    {
        $instance->callUnknownFunction();
    }
    
    /**
     * @expectedException \InvalidArgumentException
     * @depends testConstructorDefault
     * @param \AcsClient $instance
     */
    public function testMagicCall_Exception2($instance)
    {
        $instance->getUnknownProperty();
    }

    /**
     * @depends testConstructorDefault
     * @param $instance
     */
    public function testMagicCall($instance)
    {
        $this->assertInstanceOf(
            'AcsClient',
            $instance->setUsername('custom-username')
        );

        $this->assertEquals('custom-username', $instance->getUsername(), 'Expected previously set username');

        $this->assertInstanceOf(
            'AcsClient',
            $instance->setOptions(array(
                'unknownAttribute' => 'value'
            ))
        );
        $this->assertEquals('value', $instance->getUnknownAttribute());

        $defaults = array(
            'serviceRoot' => 'https://portal2.foreseeresults.com/services/',
            'requestTokenUri' => 'oauth/request_token',
            'accessTokenUri' => 'oauth/access_token',
            'authorizationUri' => 'oauth/user_authorization',
            'loginUri' => 'login',
            'sessionId' => null
        );
        foreach ($defaults as $key => $value) {
            $method = "get" . ucfirst($key);
            $this->assertEquals(
                $value,
                $instance->{$method}()
            );
        }
    }
    
    /**
     * @depends testConstructorDefault
     */
    public function testCallResource_Exception_Resource($instance)
    {
        try {
            $instance->callResource(null);
            $this->fail("Expected exception when invoking with NULL");
        } catch (\Exception $e) {
            $this->assertInstanceOf('InvalidArgumentException', $e, "Invalid argument expected when not passing parameters");
            $this->assertEquals("Unexpected \$resource provided", $e->getMessage());
        }
        
        try {
            $instance->callResource(array());
            $this->fail("Expected exception when invoking with non-string");
        } catch (\Exception $e) {
            $this->assertInstanceOf('InvalidArgumentException', $e, "Invalid argument expected when not passing invalid resource parameter");
            $this->assertEquals("Unexpected \$resource provided", $e->getMessage());
        }
        
        try {
            $instance->callResource("");
            $this->fail("Expected exception when invoking with empty string");
        } catch (\Exception $e) {
            $this->assertInstanceOf('InvalidArgumentException', $e, "Invalid argument expected when passing an empty resource URI");
            $this->assertEquals("Unexpected \$resource provided", $e->getMessage());
        }
    }
    
    /**
     * @depends testConstructorDefault
     */
    public function testCallResource_Exception_Method($instance)
    {
        try { 
            $instance->callResource("valid", new \DateTime(), array(), "callback");
            $this->fail("Expected exception when invoking with object");
        } catch (\Exception $e) {
            $this->assertInstanceOf('InvalidArgumentException', $e, "Invalid argument exception expected when passing object as method");
            $this->assertEquals("Invalid supplied method", $e->getMessage());
        }
        
        try { 
            $instance->callResource("valid", "INVALID CHOICE", array(), "callback");
            $this->fail("Expected exception when invoking with invalid choice");
        } catch (\Exception $e) {
            $this->assertInstanceOf('InvalidArgumentException', $e, "Invalid argument exception expected when passing invalid choice for method");
            $this->assertEquals("Invalid supplied method", $e->getMessage());
        }
    }

    /**
     * @depends testConstructorDefault
     * @param \AcsClient $instance
     */
    public function testCallResource_Exception_Data($instance)
    {
        try {
            $instance->callResource("valid", "GET", new \DateTime(), "callback");
            $this->fail("Exepcted exception when invoking with invalid data parameter");
        } catch (\Exception $e) {
            $this->assertInstanceOf("InvalidArgumentException", $e);
            $this->assertEquals("Expected array for extra data", $e->getMessage());
        }
    }

    public function testCallResource_FailAuth()
    {
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array(
                '_establishAuthorization'
            ))
            ->getMock();

        $instance->expects($this->once())
            ->method('_establishAuthorization')
            ->will($this->returnValue(false));

        $callback = function($obj) {
            $this->assertInstanceOf("AcsClient", $obj);
        };

        $this->assertEquals(FALSE, $instance->callResource("uri", "GET", array(), $callback));
    }

    public function testCallResource_Error()
    {
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array(
                '_establishAuthorization', '_getOAuth'
            ))
            ->getMock();

        $instance->expects($this->once())
            ->method('_establishAuthorization')
            ->will($this->returnValue(true));

        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array(
                'request', 'getLastRequest'
            ))
            ->getMock();

        $oaMock->expects($this->once())
            ->method('request')
            ->will($this->returnValue(true));

        $oaMock->expects($this->once())
            ->method('getLastRequest')
            ->will($this->returnValue(null));

        $instance->expects($this->once())
            ->method('_getOAuth')
            ->will($this->returnValue($oaMock));

        $expected = array(
            'code' => 'INVALIDREQUEST',
            'message' => "Request to 'resource' could not complete. Please try again."
        );

        $this->hasRun = false;
        $callback = function ($obj) use (&$expected) {
            $this->hasRun = true;
            $this->assertInstanceOf("AcsClient", $obj);
            $this->assertTrue($obj->isError());
            $this->assertTrue(is_array($error = $obj->getError()));
            $this->assertArrayHasKey('code', $error);
            $this->assertArrayHasKey('message', $error);
            $this->assertEquals($expected['code'], $error['code']);
            $this->assertEquals($expected['message'], $error['message']);
        };

        // Empty (bad) response from API service
        $instance->callResource(
            "/resource",
            "GET",
            array(),
            $callback
        );
        $this->assertTrue($this->hasRun, "Callback wasn't executed");
    }

    public function testCallResource_Error2()
    {
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array(
                '_establishAuthorization', '_getOAuth'
            ))
            ->getMock();

        $instance->expects($this->once())
            ->method('_establishAuthorization')
            ->will($this->returnValue(true));

        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array(
                'request', 'getLastRequest'
            ))
            ->getMock();

        $oaMock->expects($this->once())
            ->method('request')
            ->will($this->returnValue(true));

        $oaMock->expects($this->once())
            ->method('getLastRequest')
            ->will($this->returnValue(array()));

        $instance->expects($this->once())
            ->method('_getOAuth')
            ->will($this->returnValue($oaMock));

        $expected = array(
            'code' => 'INVALIDREQUEST',
            'message' => "Request to 'resource' could not complete. Please try again."
        );

        $this->hasRun = false;
        $callback = function ($obj) use (&$expected) {
            $this->hasRun = true;
            $this->assertInstanceOf("AcsClient", $obj);
            $this->assertTrue($obj->isError());
            $this->assertTrue(is_array($error = $obj->getError()));
            $this->assertArrayHasKey('code', $error);
            $this->assertArrayHasKey('message', $error);
            $this->assertEquals($expected['code'], $error['code']);
            $this->assertEquals($expected['message'], $error['message']);
        };

        // Empty (bad) response from API service
        $instance->callResource(
            "/resource",
            "GET",
            array(),
            $callback
        );
        $this->assertTrue($this->hasRun, "Callback wasn't executed");

    }

    public function testCallResource_Error_404()
    {
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array(
                '_establishAuthorization', '_getOAuth'
            ))
            ->getMock();

        $instance->expects($this->once())
            ->method('_establishAuthorization')
            ->will($this->returnValue(true));

        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array(
                'request', 'getLastRequest'
            ))
            ->getMock();

        $oaMock->expects($this->once())
            ->method('request')
            ->will($this->returnValue(true));

        $oaMock->expects($this->once())
            ->method('getLastRequest')
            ->will($this->returnValue(array(
                'info' => array(
                    'http_code' => 404
                )
            )));

        $instance->expects($this->once())
            ->method('_getOAuth')
            ->will($this->returnValue($oaMock));

        $expected = array(
            'code' => 404,
            'message' => "Unknown resource 'resource'"
        );

        $this->hasRun = false;
        $callback = function ($obj) use (&$expected) {
            $this->hasRun = true;
            $this->assertInstanceOf("AcsClient", $obj);
            $this->assertTrue($obj->isError());
            $this->assertTrue(is_array($error = $obj->getError()));
            $this->assertArrayHasKey('code', $error);
            $this->assertArrayHasKey('message', $error);
            $this->assertEquals($expected['code'], $error['code']);
            $this->assertEquals($expected['message'], $error['message']);
        };

        // Empty (bad) response from API service
        $instance->callResource(
            "/resource",
            "GET",
            array(),
            $callback
        );
        $this->assertTrue($this->hasRun, "Callback wasn't executed");

    }

    public function testCallResource_Error_403()
    {
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array(
                '_establishAuthorization', '_getOAuth'
            ))
            ->getMock();

        $instance->expects($this->once())
            ->method('_establishAuthorization')
            ->will($this->returnValue(true));

        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array(
                'request', 'getLastRequest'
            ))
            ->getMock();

        $oaMock->expects($this->once())
            ->method('request')
            ->will($this->returnValue(true));

        $oaMock->expects($this->once())
            ->method('getLastRequest')
            ->will($this->returnValue(array(
                'info' => array(
                    'http_code' => 403
                )
            )));

        $instance->expects($this->once())
            ->method('_getOAuth')
            ->will($this->returnValue($oaMock));

        $expected = array(
            'code' => 403,
            'message' => "Access denied to 'resource'"
        );

        $this->hasRun = false;
        $callback = function ($obj) use (&$expected) {
            $this->hasRun = true;
            $this->assertInstanceOf("AcsClient", $obj);
            $this->assertTrue($obj->isError());
            $this->assertTrue(is_array($error = $obj->getError()));
            $this->assertArrayHasKey('code', $error);
            $this->assertArrayHasKey('message', $error);
            $this->assertEquals($expected['code'], $error['code']);
            $this->assertEquals($expected['message'], $error['message']);
        };

        // Empty (bad) response from API service
        $instance->callResource(
            "/resource",
            "GET",
            array(),
            $callback
        );
        $this->assertTrue($this->hasRun, "Callback wasn't executed");

    }

    public function testCallResource_Error_NotString()
    {
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array(
                '_establishAuthorization', '_getOAuth'
            ))
            ->getMock();

        $instance->expects($this->once())
            ->method('_establishAuthorization')
            ->will($this->returnValue(true));

        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array(
                'request', 'getLastRequest'
            ))
            ->getMock();

        $oaMock->expects($this->once())
            ->method('request')
            ->will($this->returnValue(12345));

        $oaMock->expects($this->once())
            ->method('getLastRequest')
            ->will($this->returnValue(array(
                'info' => array(
                    'http_code' => 200
                )
            )));

        $instance->expects($this->once())
            ->method('_getOAuth')
            ->will($this->returnValue($oaMock));

        $expected = array(
            'code' => "INVALIDREQUEST",
            'message' => "Request to 'resource' could not complete. Please try again."
        );

        $this->hasRun = false;
        $callback = function ($obj) use (&$expected) {
            $this->hasRun = true;
            $this->assertInstanceOf("AcsClient", $obj);
            $this->assertTrue($obj->isError());
            $this->assertTrue(is_array($error = $obj->getError()));
            $this->assertArrayHasKey('code', $error);
            $this->assertArrayHasKey('message', $error);
            $this->assertEquals($expected['code'], $error['code']);
            $this->assertEquals($expected['message'], $error['message']);
        };

        // Empty (bad) response from API service
        $instance->callResource(
            "/resource",
            "GET",
            array(),
            $callback
        );
        $this->assertTrue($this->hasRun, "Callback wasn't executed");

    }

    public function testCallResource_Error_BadJson()
    {
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array(
                '_establishAuthorization', '_getOAuth'
            ))
            ->getMock();

        $instance->expects($this->once())
            ->method('_establishAuthorization')
            ->will($this->returnValue(true));

        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array(
                'request', 'getLastRequest'
            ))
            ->getMock();

        $oaMock->expects($this->once())
            ->method('request')
            ->will($this->returnValue("NOT JSON"));

        $oaMock->expects($this->once())
            ->method('getLastRequest')
            ->will($this->returnValue(array(
                'info' => array(
                    'http_code' => 200
                )
            )));

        $instance->expects($this->once())
            ->method('_getOAuth')
            ->will($this->returnValue($oaMock));

        $expected = array(
            'code' => "INVALIDREQUEST",
            'message' => "Request to 'resource' could not complete. Please try again."
        );

        $this->hasRun = false;
        $callback = function ($obj) use (&$expected) {
            $this->hasRun = true;
            $this->assertInstanceOf("AcsClient", $obj);
            $this->assertTrue($obj->isError());
            $this->assertTrue(is_array($error = $obj->getError()));
            $this->assertArrayHasKey('code', $error);
            $this->assertArrayHasKey('message', $error);
            $this->assertEquals($expected['code'], $error['code']);
            $this->assertEquals($expected['message'], $error['message']);
        };

        // Empty (bad) response from API service
        $instance->callResource(
            "/resource",
            "GET",
            array(),
            $callback
        );
        $this->assertTrue($this->hasRun, "Callback wasn't executed");

    }

    public function testCallResource_Simple()
    {
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array(
                '_establishAuthorization', '_getOAuth'
            ))
            ->getMock();

        $instance->expects($this->once())
            ->method('_establishAuthorization')
            ->will($this->returnValue(true));

        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array(
                'request', 'getLastRequest'
            ))
            ->getMock();

        $oaMock->expects($this->once())
            ->method('request')
            ->will($this->returnValue(json_encode(array('success'))));

        $oaMock->expects($this->once())
            ->method('getLastRequest')
            ->will($this->returnValue(array(
                'info' => array(
                    'http_code' => 200
                )
            )));

        $instance->expects($this->once())
            ->method('_getOAuth')
            ->will($this->returnValue($oaMock));

        $expected = array(
            'code' => "INVALIDREQUEST",
            'message' => "Request to 'resource' could not complete. Please try again."
        );

        $this->hasRun = false;
        $callback = function ($obj) use (&$expected) {
            $this->hasRun = true;
            $this->assertInstanceOf("AcsClient", $obj);
            $this->assertFalse($obj->isError());
        };

        // Empty (bad) response from API service
        $instance->callResource(
            "/resource",
            "GET",
            array(),
            $callback
        );
        $this->assertTrue($this->hasRun, "Callback wasn't executed");
    }


    public function testCallResource_Signatures()
    {
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array(
                '_establishAuthorization',
            ))
            ->getMock();

        $instance->expects($this->any())
            ->method('_establishAuthorization')
            ->will($this->returnValue(false));

        $this->hasRun = false;
        $callback = function ($obj) {
            $this->hasRun = true;
            $this->assertInstanceOf("AcsClient", $obj);
        };

        // Empty (bad) response from API service
        $this->assertEquals(false, $instance->callResource(
            "/resource",
            $callback
        ));
        $this->assertTrue($this->hasRun, "Callback wasn't executed");

        $this->hasRun = false;
        $this->assertEquals(false, $instance->callResource(
            "/resource",
            "GET",
            $callback
        ));
        $this->assertTrue($this->hasRun, "Callback wasn't executed");

        $this->hasRun = false;
        $this->assertEquals(false, $instance->callResource(
            "/resource",
            "GET",
            $callback
        ));
        $this->assertTrue($this->hasRun, "Callback wasn't executed");

        $this->hasRun = false;
        $this->assertEquals(false, $instance->callResource(
            "/resource",
            array(),
            $callback
        ));
        $this->assertTrue($this->hasRun, "Callback wasn't executed");

        $this->assertEquals(false, $instance->callResource(
            "/resource"
        ));

        $this->assertEquals(false, $instance->callResource(
            "/resource",
            "GET"
        ));
        $this->assertEquals(false, $instance->callResource(
            "/resource",
            array()
        ));
        $this->assertEquals(false, $instance->callResource(
            "/resource",
            "GET",
            array()
        ));
        $this->assertEquals(false, $instance->callResource(
            "/resource",
            "GET",
            array(),
            "non callable"
        ));
    }

    public function testAccessors()
    {
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(null)
            ->getMock();

        $this->assertInstanceOf('AcsClient', $instance->setUsername('username'));
        $this->assertInstanceOf('AcsClient', $instance->setPassword('password'));
        $this->assertInstanceOf('AcsClient', $instance->setConsumerKey('consumerKey'));
        $this->assertInstanceOf('AcsClient', $instance->setConsumerSecret('consumerSecret'));

        $this->assertInstanceOf('AcsClient', $instance->setLastResponse('lastResponse'));
        $this->assertEquals('lastResponse', $instance->getLastResponse());

        $this->assertFalse($instance->isError());
        $this->assertInstanceOf('AcsClient', $instance->setError('code'));
        $this->assertTrue($instance->isError());
        $this->assertEquals(array('code' => 'code', 'message' => ''), $instance->getError());

        $this->assertInstanceOf('AcsClient', $instance->setError('new-code', 'message'));
        $this->assertTrue($instance->isError());
        $this->assertEquals(array('code' => 'new-code', 'message' => 'message'), $instance->getError());

        $this->assertInstanceOf('AcsClient', $instance->setError(false));
        $this->assertFalse($instance->isError());

        $this->assertEquals(\AcsClient::SIGNATURE_METHOD_HMACSHA1, $instance->getSignatureMethod());

        $instance->setOptions(array('testOption' => 'Option Value'));
        $this->assertEquals('Option Value', $instance->getOption('testOption'));
        $this->assertEquals(null, $instance->getOption('notset'));

        try {
            $instance->setAccessToken(1235);
            $this->fail("Expected exception");
        } catch (\Exception $e) {
            $this->assertInstanceOf('InvalidArgumentException', $e);
            $this->assertEquals("Invalid access token provided. Expect string or array", $e->getMessage());
        }

        try {
            $instance->setAccessTokenSecret(1235);
            $this->fail("Expected exception");
        } catch (\Exception $e) {
            $this->assertInstanceOf('InvalidArgumentException', $e);
            $this->assertEquals("Invalid access token secret provided. Expected string", $e->getMessage());
        }

        $this->assertSame(
            $instance,
            $instance->setAccessToken('token')
        );
        $this->assertSame(
            $instance,
            $instance->setAccessTokenSecret('secret')
        );
        $token = array(
            'accessToken' => 'token',
            'accessTokenSecret' => 'secret'
        );
        $this->assertEquals(
            $token,
            $instance->getAccessToken()
        );

        $this->assertSame($instance, $instance->setAccessToken(false));
        $this->assertSame($instance, $instance->setAccessToken($token));
        $this->assertEquals($token, $instance->getAccessToken());

        $this->assertSame($instance, $instance->setAccessToken(false));
        $this->assertSame($instance, $instance->setAccessTokenSecret('secret'));
        $this->assertSame($instance, $instance->setAccessToken('token'));
        $this->assertEquals($token, $instance->getAccessToken());
    }

    public function testAuthenticate()
    {
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array('_establishAuthorization'))
            ->getMock();
        $instance->expects($this->once())
            ->method('_establishAuthorization')
            ->will($this->returnValue('return'));

        $this->assertEquals('return', $instance->authenticate());
    }

    public function testEstablishAuthorization_BadRequestToken()
    {
        /**
         * @var \AcsClient $instance
         */
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array('_getOAuth'))
            ->getMock();


        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array(
                'requestRequestToken'
            ))
            ->getMock();

        $oaMock->expects($this->once())
            ->method('requestRequestToken')
            ->will($this->returnValue(false));

        $instance->expects($this->once())
            ->method('_getOAuth')
            ->will($this->returnValue($oaMock));

        $this->assertFalse(
            $instance->authenticate(),
            "Expected a false to be returned"
        );
        $this->assertTrue($instance->isError());
        $this->assertTrue(is_array($error = $instance->getError()));
        $this->assertEquals("INVALIDREQUESTTOKEN", $error['code']);
        $this->assertEquals("Unable to retrieve request token from service.", $error['message']);
    }

    public function testEstablishAuthorization_CouldNotLogin()
    {
        /**
         * @var \AcsClient $instance
         */
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array('_getOAuth'))
            ->getMock();


        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array(
                'requestRequestToken', 'getHttpClient', 'getLoginEndpoint'
            ))
            ->getMock();

        $oaMock->expects($this->once())
            ->method('requestRequestToken')
            ->will($this->returnValue(true));

        $reqMock = $this->getMockBuilder('\OAuth\Common\Http\Client\CurlClient')
            ->setMethods(array('retrieveResponse', 'getLastRequest'))
            ->getMock();
        $reqMock->expects($this->once())
            ->method('getLastRequest')
            ->with('info')
            ->will($this->returnValue(array('http_code' => 301)));

        $oaMock->expects($this->once())
            ->method('getHttpClient')
            ->will($this->returnValue($reqMock));

        $instance->expects($this->once())
            ->method('_getOAuth')
            ->will($this->returnValue($oaMock));

        $this->assertFalse(
            $instance->authenticate(),
            "Expected a false to be returned"
        );
        $this->assertTrue($instance->isError());
        $this->assertTrue(is_array($error = $instance->getError()));
        $this->assertEquals("COULDNOTLOGIN", $error['code']);
        $this->assertEquals("Unexpected response from the OAuth service, unable to authorize.", $error['message']);
    }

    public function testEstablishAuthorization_InvalidCreds()
    {
        /**
         * @var \AcsClient $instance
         */
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array('_getOAuth'))
            ->getMock();


        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array(
                'requestRequestToken', 'getHttpClient', 'getLoginEndpoint'
            ))
            ->getMock();

        $oaMock->expects($this->once())
            ->method('requestRequestToken')
            ->will($this->returnValue(true));

        $reqMock = $this->getMockBuilder('\OAuth\Common\Http\Client\CurlClient')
            ->setMethods(array('retrieveResponse', 'getLastRequest'))
            ->getMock();
        $reqMock->expects($this->once())
            ->method('getLastRequest')
            ->with('info')
            ->will($this->returnValue(array(
                'http_code' => 302,
                'redirect_url' => 'page#loginfailed'
            )));

        $oaMock->expects($this->once())
            ->method('getHttpClient')
            ->will($this->returnValue($reqMock));

        $instance->expects($this->once())
            ->method('_getOAuth')
            ->will($this->returnValue($oaMock));

        $this->assertFalse(
            $instance->authenticate(),
            "Expected a false to be returned"
        );
        $this->assertTrue($instance->isError());
        $this->assertTrue(is_array($error = $instance->getError()));
        $this->assertEquals("INVALIDCREDENTIALS", $error['code']);
        $this->assertEquals("Unable to login, username and password are invalid.", $error['message']);
    }

    public function testEstablishAuthorization_NoAccessToken_One()
    {
        /**
         * @var \AcsClient $instance
         */
        $instance = $this->getMockBuilder('\AcsClient')->setMethods(array('_getOAuth'))->getMock();

        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array('requestRequestToken', 'getHttpClient', 'getLoginEndpoint', 'getAuthorizationEndpoint'))
            ->getMock();

        $rtMock = $this->getMockBuilder('RequestToken')->setMethods(array('getRequestToken'))->getMock();


        $reqMock = $this->getMockBuilder('\OAuth\Common\Http\Client\CurlClient')
            ->setMethods(array('retrieveResponse', 'getLastRequest'))
            ->getMock();

        $reqMock->expects($this->exactly(2))->method('getLastRequest')->will($this->onConsecutiveCalls(
            array('http_code' => 302, 'redirect_url' => 'page#success')),
            array('info' => array('http_code' => 301))
        );

        $oaMock->expects($this->once())->method('requestRequestToken')->will($this->returnValue($rtMock));
        $oaMock->expects($this->once())->method('getHttpClient')->will($this->returnValue($reqMock));

        $instance->expects($this->once())->method('_getOAuth')->will($this->returnValue($oaMock));

        $this->assertFalse(
            $instance->authenticate(),
            "Expected a false to be returned"
        );
        $this->assertTrue($instance->isError());
        $this->assertTrue(is_array($error = $instance->getError()));
        $this->assertEquals("COULDNOTGETACCESSTOKEN", $error['code']);
        $this->assertEquals("Unexpected response from the OAuth service, unable to authorize.", $error['message']);
    }

    public function testEstablishAuthorization_NoAccessToken_Two()
    {
        /**
         * @var \AcsClient $instance
         */
        $instance = $this->getMockBuilder('\AcsClient')->setMethods(array('_getOAuth'))->getMock();

        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array('requestRequestToken', 'getHttpClient', 'getLoginEndpoint', 'getAuthorizationEndpoint'))
            ->getMock();

        $rtMock = $this->getMockBuilder('RequestToken')->setMethods(array('getRequestToken'))->getMock();


        $reqMock = $this->getMockBuilder('\OAuth\Common\Http\Client\CurlClient')
            ->setMethods(array('retrieveResponse', 'getLastRequest'))
            ->getMock();

        $reqMock->expects($this->exactly(2))->method('getLastRequest')->will($this->onConsecutiveCalls(
            array('http_code' => 302, 'redirect_url' => 'page#success'),
            array('info' => array('http_code' => '302', 'redirect_url' => 'no_question_mark'))
        ));

        $oaMock->expects($this->once())->method('requestRequestToken')->will($this->returnValue($rtMock));
        $oaMock->expects($this->once())->method('getHttpClient')->will($this->returnValue($reqMock));

        $instance->expects($this->once())->method('_getOAuth')->will($this->returnValue($oaMock));

        $this->assertFalse(
            $instance->authenticate(),
            "Expected a false to be returned"
        );
        $this->assertTrue($instance->isError());
        $this->assertTrue(is_array($error = $instance->getError()));
        $this->assertEquals("COULDNOTGETACCESSTOKEN", $error['code']);
        $this->assertEquals("Unexpected response from the OAuth service, unable to authorize.", $error['message']);
    }

    public function testEstablishAuthorization_NoVerifier()
    {
        /**
         * @var \AcsClient $instance
         */
        $instance = $this->getMockBuilder('\AcsClient')->setMethods(array('_getOAuth'))->getMock();

        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array('requestRequestToken', 'getHttpClient', 'getLoginEndpoint', 'getAuthorizationEndpoint'))
            ->getMock();

        $rtMock = $this->getMockBuilder('RequestToken')->setMethods(array('getRequestToken'))->getMock();


        $reqMock = $this->getMockBuilder('\OAuth\Common\Http\Client\CurlClient')
            ->setMethods(array('retrieveResponse', 'getLastRequest'))
            ->getMock();

        $reqMock->expects($this->exactly(2))->method('getLastRequest')->will($this->onConsecutiveCalls(
            array('http_code' => '302', 'redirect_url' => 'page#success'),
            array('info' => array('http_code' => '302', 'redirect_url' => 'url?invalid=variable'))
        ));

        $oaMock->expects($this->once())->method('requestRequestToken')->will($this->returnValue($rtMock));
        $oaMock->expects($this->once())->method('getHttpClient')->will($this->returnValue($reqMock));

        $instance->expects($this->once())->method('_getOAuth')->will($this->returnValue($oaMock));

        $this->assertFalse(
            $instance->authenticate(),
            "Expected a false to be returned"
        );
        $this->assertTrue($instance->isError());
        $this->assertTrue(is_array($error = $instance->getError()));
        $this->assertEquals("COULDNOTFINDVERIFIER", $error['code']);
        $this->assertEquals("Unexpected response from OAuth service, unable to complete authorization.", $error['message']);
    }

    public function testEstablishAuthorization_BadVerufier()
    {
        /**
         * @var \AcsClient $instance
         */
        $instance = $this->getMockBuilder('\AcsClient')->setMethods(array('_getOAuth'))->getMock();

        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array('requestRequestToken', 'getHttpClient', 'getLoginEndpoint', 'getAuthorizationEndpoint'))
            ->getMock();

        $rtMock = $this->getMockBuilder('RequestToken')->setMethods(array('getRequestToken'))->getMock();


        $reqMock = $this->getMockBuilder('\OAuth\Common\Http\Client\CurlClient')
            ->setMethods(array('retrieveResponse', 'getLastRequest'))
            ->getMock();

        $reqMock->expects($this->exactly(2))->method('getLastRequest')->will($this->onConsecutiveCalls(
            array('http_code' => '302', 'redirect_url' => 'page#success'),
            array('info' => array('http_code' => '302', 'redirect_url' => 'url?oauth_verifier=A'))
        ));

        $oaMock->expects($this->once())->method('requestRequestToken')->will($this->returnValue($rtMock));
        $oaMock->expects($this->once())->method('getHttpClient')->will($this->returnValue($reqMock));

        $instance->expects($this->once())->method('_getOAuth')->will($this->returnValue($oaMock));

        $this->assertFalse(
            $instance->authenticate(),
            "Expected a false to be returned"
        );
        $this->assertTrue($instance->isError());
        $this->assertTrue(is_array($error = $instance->getError()));
        $this->assertEquals("COULDNOTFINDVERIFIER", $error['code']);
        $this->assertEquals("Unexpected response from OAuth service, unable to complete authorization.", $error['message']);
    }

    public function testEstablishAuthorization_couldNotGetAccessToken()
    {
        /**
         * @var \AcsClient $instance
         */
        $instance = $this->getMockBuilder('\AcsClient')->setMethods(array('_getOAuth'))->getMock();

        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array('requestRequestToken', 'getHttpClient', 'getLoginEndpoint', 'getAuthorizationEndpoint', 'setHttpClient', 'requestAccessToken'))
            ->getMock();

        $rtMock = $this->getMockBuilder('RequestToken')->setMethods(array('getRequestToken', 'getRequestTokenSecret'))->getMock();


        $reqMock = $this->getMockBuilder('\OAuth\Common\Http\Client\CurlClient')
            ->setMethods(array('retrieveResponse', 'getLastRequest'))
            ->getMock();

        $reqMock->expects($this->exactly(2))->method('getLastRequest')->will($this->onConsecutiveCalls(
            array('http_code' => '302', 'redirect_url' => 'page#success'),
            array('info' => array('http_code' => '302', 'redirect_url' => 'url?oauth_verifier=VALID'))
        ));

        $oaMock->expects($this->once())->method('requestRequestToken')->will($this->returnValue($rtMock));
        $oaMock->expects($this->once())->method('getHttpClient')->will($this->returnValue($reqMock));

        $instance->expects($this->once())->method('_getOAuth')->will($this->returnValue($oaMock));

        $this->assertFalse(
            $instance->authenticate(),
            "Expected a false to be returned"
        );
        $this->assertTrue($instance->isError());
        $this->assertTrue(is_array($error = $instance->getError()));
        $this->assertEquals("COULDNOTGETACCESSTOKENNULL", $error['code']);
        $this->assertEquals("Unable to retrieve access token, please try again.", $error['message']);
    }

    public function testEstablishAuthorization()
    {
        /**
         * @var \AcsClient $instance
         */
        $instance = $this->getMockBuilder('\AcsClient')->setMethods(array('_getOAuth'))->getMock();

        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array('requestRequestToken', 'getHttpClient', 'getLoginEndpoint', 'getAuthorizationEndpoint', 'setHttpClient', 'requestAccessToken'))
            ->getMock();

        $rtMock = $this->getMockBuilder('RequestToken')->setMethods(array('getRequestToken', 'getRequestTokenSecret'))->getMock();


        $reqMock = $this->getMockBuilder('\OAuth\Common\Http\Client\CurlClient')
            ->setMethods(array('retrieveResponse', 'getLastRequest'))
            ->getMock();

        $reqMock->expects($this->exactly(2))->method('getLastRequest')->will($this->onConsecutiveCalls(
            array('http_code' => '302', 'redirect_url' => 'page#success'),
            array('info' => array('http_code' => '302', 'redirect_url' => 'url?oauth_verifier=VALID'))
        ));

        $atMock = $this->getMockBuilder('AccessToken')->setMethods(array('getAccessToken', 'getAccessTokenSecret'))->getMock();
        $atMock->expects($this->once())->method('getAccessToken')->will($this->returnValue('accessToken'));
        $atMock->expects($this->once())->method('getAccessTokenSecret')->will($this->returnValue('accessTokenSecret'));

        $oaMock->expects($this->once())->method('requestRequestToken')->will($this->returnValue($rtMock));
        $oaMock->expects($this->once())->method('getHttpClient')->will($this->returnValue($reqMock));

        $oaMock->expects($this->once())->method('requestAccessToken')->will($this->returnValue($atMock));
        $instance->expects($this->exactly(2))->method('_getOAuth')->will($this->returnValue($oaMock));

        $this->assertSame(
            $instance,
            $instance->authenticate()
        );
        $this->assertFalse($instance->isError());

        $this->assertSame(
            $instance,
            $this->invokeMethod($instance, '_establishAuthorization', array())
        );
    }

    public function testEstablishAuthorization_Exception()
    {
        /**
         * @var \AcsClient $instance
         */
        $instance = $this->getMockBuilder('\AcsClient')
            ->setMethods(array('_getOAuth'))
            ->getMock();


        $oaMock = $this->getMockBuilder('\OAuth\OAuth1\Service\Foresee')
            ->disableOriginalConstructor()
            ->setMethods(array(
                'requestRequestToken'
            ))
            ->getMock();

        $oaMock->expects($this->once())
            ->method('requestRequestToken')
            ->will($this->throwException(new \Exception('Testing Message')));

        $instance->expects($this->once())
            ->method('_getOAuth')
            ->will($this->returnValue($oaMock));

        $this->assertFalse(
            $instance->authenticate(),
            "Expected a false to be returned"
        );
        $this->assertTrue($instance->isError());
        $this->assertTrue(is_array($error = $instance->getError()));
        $this->assertEquals("COULDNOTLOGIN", $error['code']);
        $this->assertEquals("Error while authorizing. Testing Message", $error['message']);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid arguments, date creation requires at least one date parameter
     * @group getDateObject
     */
    public function testGetDateObject_Exception()
    {
        $instance = $this->getMockBuilder('\AcsClient')->setMethods(null)->getMock();
        $instance->getDateObject('clientid', null);
    }

    /**
     * @group getDateObject
     */
    public function testGetDateObject()
    {
        $instance = $this->getMockBuilder('\AcsClient')->setMethods(null)->getMock();

        $this->assertTrue(is_array(
            $instance->getDateObject(
                'clientid',
                '2015-01-01'
            )
        ));

        $this->assertTrue(is_array(
            $instance->getDateObject(
                'clientid',
                '2015-01-01',
                '2015-10-01'
            )
        ));

        $this->assertTrue(is_array(
            $instance->getDateObject(
                'clientid',
                '2015-01-01',
                '2015-10-01',
                'style'
            )
        ));

        $this->assertTrue(is_array(
            $instance->getDateObject(
                'clientid',
                '2015-01-01',
                '2015-10-01',
                'style',
                'option'
            )
        ));

        $this->assertTrue(is_array(
            $instance->getDateObject(
                'clientid',
                '2015-01-01',
                '2015-10-01',
                'style',
                'option',
                'fiscal'
            )
        ));

        $this->assertTrue(is_array(
            $instance->getDateObject(
                'clientid',
                '2015-01-01',
                '2015-10-01',
                'style',
                'option',
                'fiscal',
                'extra'
            )
        ));

        $this->assertTrue(is_array(
            $instance->getDateObject(
                'clientid',
                '2015-01-01',
                new \DateTime()
            )
        ));

        $this->assertTrue(is_array(
            $instance->getDateObject(
                'clientid',
                new \DateTIme('2015-01-01'),
                new \DateTime('2015-10-01')
            )
        ));
    }

    /**
     * Call protected/private method of a class.
     *
     * @param object &$object Instantiated object that we will run method on.
     * @param string $methodName Method name to call
     * @param array $parameters Array of parameters to pass into method.
     *
     * @return mixed Method return.
     */
    public function invokeMethod(&$object, $methodName, array $parameters = array())
    {
        $reflection = new \ReflectionClass(get_class($object));
        $method = $reflection->getMethod($methodName);
        $method->setAccessible(true);

        return $method->invokeArgs($object, $parameters);
    }
}