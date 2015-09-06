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
            $callback();
            return;
        }

        echo "SUCCESS";
        return $this;
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

            $client = new \OAuth\Common\Http\Client\CurlClient('ACSOAuthLibrary');
            $client->setMaxRedirects(0);

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

    protected function _establishAuthorization()
    {
        $oa = $this->_getOAuth();

        try {
            $this->_oaData['requestToken'] = $requestToken = $oa->requestRequestToken();

            if (!$requestToken) {
                // Add error return false
            }

            /**
             * @var \OAuth\Common\Http\Client\CurlClient $request
             */
            $request = $oa->getHttpClient();
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
                // ERROR
                $b = 5;
            }
            $redirectUrl = $info['redirect_url'];
            if (strpos($redirectUrl, '#loginfailed') !== FALSE) {
                // ERROR
                $c = 5;
            }

            $headers = $request->getLastRequest('headers');
            $cookies = array();
            foreach ((array)$headers['set-cookie'] as $cookie) {
                $cookie = explode(';', trim($cookie));
                $cookie = explode('=', $cookie[0]);
                $cookies[trim($cookie[0])] = trim($cookie[1]);
            }
            print_r($cookies);
            $this->_setCookie($cookies);
            $cookies = $this->_getCookie();
            $cookies['CONSUMER_TYPE'] = $this->getConsumerType();

            $cookies = array_map(function($v, $k) {
                return "{$k}={$v}";
            }, $cookies, array_keys($cookies));
            $cookies = implode("; ", $cookies);

            $request->setCurlParameters(array(CURLOPT_COOKIE => $cookies));

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
                // ERROR
                $a = 5;
                die('No redirect');
            }

            $url = $info['redirect_url'];
            if (strpos($url, '?') === FALSE) {
                // ERROR
                $a = 6;
                die('no url');
            }

            list($host, $url) = explode('?', $url, 2);
            parse_str($url, $values);
            if (!isset($values['oauth_verifier']) || strlen($values['oauth_verifier']) < 2) {
                // ERROR
                $a = 7;
                die('no verifier');
            }
            $headers = $request->getLastRequest('headers');
            $cookies = array();
            foreach ((array)$headers['set-cookie'] as $cookie) {
                $cookie = explode(';', trim($cookie));
                $cookie = explode('=', $cookie[0]);
                $cookies[trim($cookie[0])] = trim($cookie[1]);
            }
            print_r($cookies);
            $this->_setCookie($cookies);
            $cookies = $this->_getCookie();
            $cookies = array_map(function($v, $k) {
                return "{$k}={$v}";
            }, $cookies, array_keys($cookies));
            $cookies = implode("; ", $cookies);

            $request->setCurlParameters(array(CURLOPT_COOKIE => $cookies));
            
            $this->_oaData['oauth_verifier'] = $values['oauth_verifier'];

            $oa->setHttpClient($request);
            $accessToken = $oa->requestAccessToken(
                $requestToken->getRequestToken(),
                $this->_oaData['oauth_verifier'],
                $requestToken->getRequestTokenSecret()
            );
            $a = 5;
        } catch (Exception $e) {
            // Add error
            echo "ERROR: " . $e->getMessage() . PHP_EOL;
        }
        return true;
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

    protected function _setCookie($cookie, $value = null)
    {
        if (!$value && is_array($cookie)) {
            foreach ($cookie as $c => $v) {
                $this->_setCookie($c, $v);
            }
            return $this;
        }

        if (!isset($this->_oaData['cookies'])) {
            $this->_oaData['cookies'] = array();
        }
        $this->_oaData['cookies'][$cookie] = $value;
        return $this;
    }

    public function _getCookie($cookie = null)
    {
        if (!$cookie) {
            return $this->_oaData['cookies'] ?: array();
        }
        if (isset($this->_oaData['cookies']) && isset($this->_oaData['cookies'][$cookie])) {
            return $this->_oaData['cookies'][$cookie];
        }
        return null;
    }
}
