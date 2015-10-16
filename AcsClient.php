<?php

class AcsClient
{
    const SIGNATURE_METHOD_HMACSHA1 = "HMAC-SHA1";

    public function __construct(array $config = array())
    {        
        $this->setOptions($config);
    }

    /**
     * Sets internal options from provided array. Will use individual setters if option key matches method name
     *
     * @param array $options
     * @return $this
     */
    public function setOptions(array $options)
    {
        foreach ($options as $key => $value) {
            $method = "set" . ucfirst($key);
            if (method_exists($this, $method)) {
                $this->{$method}($value);
            } else {
                $this->_options[$key] = $value;
            }
        }
        return $this;
    }

    /**
     * Magic function implements proxy "get*" functions
     *
     * @param string $name
     * @param array $arguments
     * @return mixed
     * @throws InvalidArgumentException
     */
    public function __call($name, $arguments)
    {
        if (substr($name, 0, 3) === "get") {
            $attribute = "_" . ($property = lcfirst(substr($name, 3)));
            if (property_exists($this, $attribute)) {
                return $this->{$attribute};
            }
            if (isset($this->_options[$property])) {
                return $this->_options[$property];
            }
        }
        throw new InvalidArgumentException("Method not defined '$name'");
    }

    public function callResource($resource, $method = null, $data = null, $callback = null)
    {
        if (!is_string($resource) || !$resource) {
            throw new \InvalidArgumentException("Unexpeted \$resource provided");
        }

        $defaultMethod = "GET";
        if (is_callable($method)) {
            $callback = $method;
            $data = array();
            $method = $defaultMethod;
        }
        if (is_callable($data)) {
            $callback = $data;
            $data = array();
        }

        $method = strtoupper(trim($method)) ?: $defaultMethod;
        if (!in_array($method, array("GET", "POST", "DELETE", "PUT"))) {
            throw new InvalidArgumentException("Invalid supplied method '{$method}'");
        }

        $data = $data ?: array();
        if (!is_array($data)) {
            throw new InvalidArgumentException("Expected array for extra data");
        }
        if (!$callback || !is_callable($callback)) {
            $callback = function() { /* no op */ };
        }

        /* Clean the path */
        $resource = str_replace("\\", "/", $resource);
        if ($resource[0] == "/") {
            $resource = substr($resource, 1);
        }

        if (!$this->_establishAuthorization()) {
            $callback($this);
            return false;
        }

        $uri = new \OAuth\Common\Http\Uri\Uri($this->getOption('serviceRoot') . $resource);

        $oa = $this->_getOAuth();
        $response = $oa->request(
            $resource,
            $method,
            null,
            array()
        );
        if (is_string($response)) {
            $response = json_decode($response, true);
        }
        $this->setError(false);
        $this->setLastResponse($response);

        $callback($this);
        return $this;
    }

    public function getDateObject($clientId, $date)
    {
        $arguments = func_get_args();

        // Remove the client id
        array_shift($arguments);
        if (!count($arguments) || !$from = array_shift($arguments)) {
            throw new \InvalidArgumentException("Invalid arguments, date creation requires at least one date parameter");
        }

        $to = $style = $fiscal = $option = null;
        if ($arguments) {
            if (is_object($fiscal = end($arguments))) {
                $fiscal = null;
            }
            if (count($arguments) > 4) {
                $arguments = array_slice($arguments, 0, 4);
            }
            switch (count($arguments)) {
                case 4:
                    list($to, $style, $option, $fiscal) = $arguments;
                    break;
                case 3:
                    list($to, $style, $option) = $arguments;
                    break;

                case 2:
                    list($to, $style) = $arguments;
                    $option = $style;
                    break;
                case 1:
                    $to = $arguments[0];
                    $option = $style = $to;
                    break;
            }
        }
        require_once __DIR__ . '/vendor/ForeseeDate.php';
        return \ForeseeDate::create($clientId, $from, $to, $style, $fiscal, $option);
    }

    public function setUsername($username)
    {
        $this->_username = $username;
        return $this;
    }

    public function setPassword($password)
    {
        $this->_password = $password;
        return $this;
    }

    public function setConsumerKey($key)
    {
        $this->_consumerKey = $key;
        return $this;
    }

    public function setConsumerSecret($secret)
    {
        $this->_consumerSecret = $secret;
        return $this;
    }

    public function setLastResponse($response)
    {
        $this->_lastResponse = $response;
    }

    public function getLastResponse()
    {
        return $this->_lastResponse;
    }


    public function setError($error)
    {
        $this->_error = $error;
    }

    public function isError()
    {
        return !!$this->_error;
    }

    public function getError()
    {
        return $this->_error;
    }

    public function getSignatureMethod()
    {
        return $this->_signatureMethod ?: static::SIGNATURE_METHOD_HMACSHA1;
    }

    public function getOption($option)
    {
        if (isset($this->_options[$option])) {
            return $this->_options[$option];
        }

        return null;
    }


    protected $_consumerKey;
    protected $_consumerSecret;
    protected $_signatureMethod;

    protected $_username;
    protected $_password;


    protected $_lastResponse = null;
    protected $_error = false;

    /**
     * Options array
     * @var array
     */
    protected $_options = array(
        'serviceRoot' => 'https://portal2.foreseeresults.com/services/',
        'requestTokenUri' => 'oauth/request_token',
        'accessTokenUri' => 'oauth/access_token',
        'authorizationUri' => 'oauth/user_authorization',
        'loginUri' => 'login',
        'sessionId' => null
    );

    /**
     *
     * @var \OAuth\OAuth1\Service\Foresee
     */
    protected $_oa = null;

    protected $_oaData = array();
    
    protected function _getOAuth()
    {
        if (!$this->_oa) {
            require_once __DIR__  . '/vendor/OAuth/bootstrap.php';

            $credentials = new \OAuth\Common\Consumer\Credentials(
                $this->getConsumerKey(),
                $this->getConsumerSecret(),
                'oob'
            );

            $cookieJar = tempnam(sys_get_temp_dir(), "acs_");
            $this->setOptions(array('cookieJar' => $cookieJar));

            $client = new \OAuth\Common\Http\Client\CurlClient('ACSOAuthLibrary');
            $client->setMaxRedirects(0);
            $client->setCurlParameters(array(
                CURLOPT_COOKIEFILE => $cookieJar,
                CURLOPT_COOKIEJAR => $cookieJar
            ));

            $storage = new \OAuth\Common\Storage\Memory();

            $signature = new \OAuth\OAuth1\Signature\Signature($credentials);
            $signature->setHashingAlgorithm($this->getSignatureMethod());

            $baseUri = new \OAuth\Common\Http\Uri\Uri($this->getOption('serviceRoot'));

            $this->_oa = new \OAuth\OAuth1\Service\Foresee(
                $credentials,
                $client,
                $storage,
                $signature,
                $baseUri
            );
        }

        return $this->_oa;
    }

    protected function _finishOAuth()
    {
        if ($this->_oa) {
            if ($cj = $this->getOption('cookieJar')) {
                @unlink($cj);
            }
        }
    }

    protected function _establishAuthorization()
    {
        if (isset($this->_oaData['accessToken'])) {
            return true;
        }

        $oa = $this->_getOAuth();

        try {
            /**
             * *** REQUEST TOKEN
             */
            $this->_oaData['requestToken'] = $requestToken = $oa->requestRequestToken();

            if (!$requestToken) {
                // Add error return false
                $this->setError("Unable to retrieve authorization token from service.");
                return false;
            }

            /**
             * @var \OAuth\Common\Http\Client\CurlClient $request
             */
            $request = $oa->getHttpClient();

            /**
             * LOGIN
             */
            $response = $request->retrieveResponse(
                $oa->getLoginEndpoint(),
                array(
                    'j_username' => $this->getUsername(),
                    'j_password' => $this->getPassword()
                ),
                array(),
                "POST"
            );

            $info = $request->getLastRequest('info');
            if ($info['http_code'] != 302) {
                $this->setError("Unexpected response from the OAuth service, unable to authorize.");
                return false;
            }

            $redirectUrl = $info['redirect_url'];
            if (strpos($redirectUrl, '#loginfailed') !== FALSE) {
                $this->setError("Unable to login, username and password are invalid.");
                return false;
            }

            /**
             * CHECK AUTHORIZATION / GET VERIFIER
             */
            $response = $request->retrieveResponse(
                $this->_oa->getAuthorizationEndpoint(array(
                    'oauth_token' => $requestToken->getRequestToken()
                )),
                null,
                array(),
                "GET"
            );
            $last = $request->getLastRequest();
            $info = $last['info'];
            if ($info['http_code'] != '302') {
                $this->setError("Unexpected response from the OAuth service, unable to authorize.");
                return false;
            }

            $url = $info['redirect_url'];
            if (strpos($url, '?') === FALSE) {
                $this->setError("Unexpected response from the OAuth service, unable to authorize.");
                return false;
            }

            list($host, $url) = explode('?', $url, 2);
            parse_str($url, $values);
            if (!isset($values['oauth_verifier']) || strlen($values['oauth_verifier']) < 2) {
                $this->setError("Unexpected response from OAuth service, unable to complete authorization.");
                return false;
            }

            $this->_oaData['oauth_verifier'] = $values['oauth_verifier'];

            /**
             * ACCESS TOKEN
             */
            $oa->setHttpClient($request);
            $accessToken = $oa->requestAccessToken(
                $requestToken->getRequestToken(),
                $this->_oaData['oauth_verifier'],
                $requestToken->getRequestTokenSecret()
            );

            $this->_oaData['accessToken'] = $accessToken;

            return true;
        } catch (Exception $e) {
            // Add error
            $this->setError("Error while authorizing. " . $e->getMessage());
            return false;
        }
    }

    protected function _generateResourceUri($resource, $params = array())
    {
        $url = $this->getOption('serviceRoot') . $resource;
        if ($params) {
            if (strpos($url, "?") === FALSE) {
                $url .= "?";
            }
            $url .= http_build_query($params);
        }
        return $url;
    }

    protected function _extractCookies($headerString)
    {
        $headerString = str_replace("\r\n", "\n", $headerString);
        $lines = explode("\n", $headerString);

        $cookies = array();
        foreach ($lines as $line) {
            $pieces = explode(":", $line, 2);
            if (count($pieces) == 2) {
                if (strtolower($pieces[0]) == "set-cookie") {
                    $pieces = explode(";", $pieces[1]);
                    $cookie = trim($pieces[0]);
                    $cookie = explode('=', $cookie);
                    $cookies[strtolower($cookie[0])] = $cookie[1];
                }
            }
        }
        return $cookies;
    }
}
