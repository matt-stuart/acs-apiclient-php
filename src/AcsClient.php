<?php
/**
 * The MIT License (MIT)
 * Copyright (c) 2015 Answers Cloud Services
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @copyright Answers Cloud Services
 * @author Matthew Stuart <matthew.stuart@answers.com>
 */

/**
 * The ACS API Client Library
 * Provides a library for interaction abstraction with the ACS API {@see http://bit.ly/15uYi0k}
 */
class AcsClient
{
    /**
     * Signature Method - HMAC-SHA1
     * @var string
     */
    const SIGNATURE_METHOD_HMACSHA1 = "HMAC-SHA1";

    /**
     * Default construction passes the optional $config variable to the option parser
     * @param array $config OPTIONAL array of options
     */
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
            if (array_key_exists($property, $this->_options)) {
                return $this->_options[$property];
            }
        }
        throw new InvalidArgumentException("Method not defined '$name'");
    }

    /**
     * Primary entry point
     * Function handles the interaction with the ACS API including necessary authentication steps should they be required.
     * This function accepts multiple parameter patterns:
     * <pre>
     *      callResource(string $resource)
     *      callResource(string $resource, function $callback)
     *      callResource(string $resource, string $method)
     *      callResource(string $resource, string $method, array $data)
     *      callResource(string $resource, string $method, function $callback)
     *      callResource(string $resource, array $data, function $callback)
     *      callResource(string $resource, string $method, array $data, function $callback)
     * </pre>
     *
     * @param string $resource URI for ACS API endpoint
     * @param string $method HTTP Method to use for communication, Default: GET
     * @param array $data Optional extra data to provide during the API request
     * @param callable $callback Callback to be executed on completion o the request. Called on success and failure
     * @throws InvalidArgumentException
     * @return $this|bool When the request fails, FALSE is returned otherwise an instance of $this for chaining
     */
    public function callResource($resource, $method = "", $data = null, $callback = null)
    {
        if (!is_string($resource) || !$resource) {
            throw new \InvalidArgumentException("Unexpected \$resource provided");
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
        if (is_array($method)) {
            $data = $method;
            $method = $defaultMethod;
        }

        if (
            !is_string($method) ||
            !($method = strtoupper(trim($method)) ?: $defaultMethod) ||
            !in_array($method, array("GET", "POST", "DELETE", "PUT"))
        ) {
            throw new InvalidArgumentException("Invalid supplied method");
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

        $oa = $this->_getOAuth();
        $response = $oa->request(
            $resource,
            $method,
            null,
            array()
        );

        $info = $oa->getLastRequest();
        if (!(is_array($info) && isset($info['info']) && isset($info['info']['http_code']) && $info['info']['http_code'] == 200)) {
            // Error State
            $info = (array)$info;
            $http_code = 0;
            if (isset($info['info']) && isset($info['info']['http_code'])) {
                $http_code = $info['info']['http_code'];
            }
            switch ($http_code) {
                case 404:
                    $this->setError("404", "Unknown resource '$resource'");
                    break;
                case 403:
                    $this->setError("403", "Access denied to '$resource'");
                    break;
                default:
                    $this->setError("INVALIDREQUEST", "Request to '$resource' could not complete. Please try again.");
                    break;
            }
        } else if (!is_string($response) || !$response = json_decode($response, true)) {
            $this->setError("INVALIDREQUEST", "Request to '$resource' could not complete. Please try again.");
        }

        if ($this->isError()) {
            $callback($this);
            return false;
        }

        $this->setError(false);
        $this->setLastResponse($response);
        $callback($this);

        return $this;
    }

    /**
     * Helper function to retrieve a properly formatted DATE reference object. This date object is formatted in a way
     * that the ACS API can understand the request properly, it supports moment in time and time range options.
     *
     *
     * @param string $clientId Customer client ID used for fiscal based dates
     * @param mixed $date,... Date operators and operands see readme
     * @return array|bool FALSE on error, array of date details when successful
     */
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

        if (!class_exists('AcsDate', false)) {
            require_once __DIR__ . '/AcsDate.php';
        }
        return \AcsDate::create($clientId, $from, $to, $style, $fiscal, $option);
    }

    /**
     * Setter: Sets internal username for auth
     * @param string $username
     * @return $this
     */
    public function setUsername($username)
    {
        $this->_username = $username;
        return $this;
    }

    /**
     * Setter: Sets internal password for auth
     * @param $password
     * @return $this
     */
    public function setPassword($password)
    {
        $this->_password = $password;
        return $this;
    }

    /**
     * Setter: Sets internal consumer key parameter
     * @param $key
     * @return $this
     */
    public function setConsumerKey($key)
    {
        $this->_consumerKey = $key;
        return $this;
    }

    /**
     * Setter: Sets internal consumer secret
     * @param $secret
     * @return $this
     */
    public function setConsumerSecret($secret)
    {
        $this->_consumerSecret = $secret;
        return $this;
    }

    /**
     * Seter: Sets internal last response instance
     * @param $response
     * @return $this;
     */
    public function setLastResponse($response)
    {
        $this->_lastResponse = $response;
        return $this;
    }

    /**
     * Getter: Retrieves last response instance
     * @return null
     */
    public function getLastResponse()
    {
        return $this->_lastResponse;
    }

    /**
     * Setter: Sets internal error tracker
     *
     * @param string $code Short code, see readme
     * @param string $message Long message description indicating error
     * @return $this
     */
    public function setError($code, $message = "")
    {
        if ($code) {
            $code = array(
                'code' => $code,
                'message' => $message
            );
        }
        $this->_error = $code;
        return $this;
    }

    /**
     * State: Indicates if current error state
     * @return bool
     */
    public function isError()
    {
        return !!$this->_error;
    }

    /**
     * Getter: Retrieves the current error instance
     * @return bool
     */
    public function getError()
    {
        return $this->_error;
    }

    /**
     * Getter: retrieves the currently set signature method or {@see SIGNATURE_METHOD_HMACSHA1} by default
     * @return string
     */
    public function getSignatureMethod()
    {
        return $this->_signatureMethod ?: static::SIGNATURE_METHOD_HMACSHA1;
    }

    /**
     * Getter: Retrieves option value for specified option key
     * @param string $option Option key to retrieve
     * @return mixed
     */
    public function getOption($option)
    {
        if (isset($this->_options[$option])) {
            return $this->_options[$option];
        }

        return null;
    }

    /**
     * Setter: Sets internal access token instance. The access token is stored as an array internally consisting of the token
     * and the associated secret.
     * <pre>
     *  accessToken = [
     *      accessToken => value,
     *      accessTokenSecret => value
     *  ]
     * </pre>
     *
     * @param string|array $token
     * @return $this
     */
    public function setAccessToken($token)
    {
        if (!$token) {
            $this->_accessToken = null;
            return $this;
        }

        if (is_string($token)) {
            $token = array('accessToken' => $token);
            if (is_array($this->_accessToken)) {
                $token = array_merge($this->_accessToken, $token);
            }
        }
        if (!is_array($token)) {
            throw new \InvalidArgumentException("Invalid access token provided. Expect string or array");
        }

        $this->_accessToken = $token;
        return $this;
    }

    /**
     * Setter: Sets the internal access token secret value
     * @param string $secret
     * @return $this
     */
    public function setAccessTokenSecret($secret)
    {
        if (!is_string($secret)) {
            throw new \InvalidArgumentException("Invalid access token secret provided. Expected string");
        }

        if (!is_array($this->_accessToken)) {
            $this->_accessToken = array();
        }
        $this->_accessToken['accessTokenSecret'] = $secret;
        return $this;
    }

    /**
     * Getter: Retrieves the internal access token detail specifier {@see setAccessToken}
     * @return array
     */
    public function getAccessToken()
    {
        return $this->_accessToken;
    }

    /**
     * Force authentication process
     *
     * @return bool
     */
    public function authenticate()
    {
        $this->_oa = null;
        $this->_oaData = array();
        $this->_accessToken = null;

        return $this->_establishAuthorization();
    }


    /**
     * Consumer Key
     * @var string
     */
    protected $_consumerKey;

    /**
     * Consumer Key Secret
     * @var string
     */
    protected $_consumerSecret;

    /**
     * Access Token
     * <pre>
     *  [
     *      accessToken => value,
     *      accessTokenSecret => value
     *  ]
     * </pre>
     *
     * @var array
     */
    protected $_accessToken;

    /**
     * Signature method to use
     * @var string
     */
    protected $_signatureMethod;

    /**
     * Username value to use for authentication
     * @var string
     */
    protected $_username;

    /**
     * Password value to use for authentication
     * @var string
     */
    protected $_password;

    /**
     * Last response from API interaction
     * @var array
     */
    protected $_lastResponse = null;

    /**
     * Error instance
     * <pre>
     *  [
     *      'code' => value,
     *      'description' => value
     *  ]
     * </pre>
     * @var bool|array
     */
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
     * Internal OAuth instance
     * @var \OAuth\OAuth1\Service\Foresee
     */
    protected $_oa = null;

    /**
     * Internal OAuth cache data object
     * @var array
     */
    protected $_oaData = array();

    /**
     * Retrieves the OAuth instance, creates new instance and preforms authentication process should it be not done
     *
     * @return \OAuth\OAuth1\Service\Foresee
     * @codeCoverageIgnore
     */
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

            if ($this->_accessToken) {
                $token = $this->_oa->createAccessToken(array(
                    'oauth_token' => $this->_accessToken['accessToken'],
                    'oauth_token_secret' => $this->_accessToken['accessTokenSecret']
                ));
                $this->_oa->setAccessToken($token);
                $this->_oaData['accessToken'] = $token;
            }
        }

        return $this->_oa;
    }

    /**
     * Processes the authorization request and establishes credentials with the ACS API OAUTH System
     * @return bool
     */
    protected function _establishAuthorization()
    {
        $oa = $this->_getOAuth();

        if (isset($this->_oaData['accessToken'])) {
            return $this;
        }

        try {
            /**
             * *** REQUEST TOKEN
             */
            $this->_oaData['requestToken'] = $requestToken = $oa->requestRequestToken();

            if (!$requestToken) {
                // Add error return false
                $this->setError("INVALIDREQUESTTOKEN", "Unable to retrieve request token from service.");
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
                $this->setError("COULDNOTLOGIN", "Unexpected response from the OAuth service, unable to authorize.");
                return false;
            }

            $redirectUrl = $info['redirect_url'];
            if (strpos($redirectUrl, '#loginfailed') !== FALSE) {
                $this->setError("INVALIDCREDENTIALS", "Unable to login, username and password are invalid.");
                return false;
            }

            /**
             * CHECK AUTHORIZATION / GET VERIFIER
             */
            $response = $request->retrieveResponse(
                $oa->getAuthorizationEndpoint(array(
                    'oauth_token' => $requestToken->getRequestToken()
                )),
                null,
                array(),
                "GET"
            );
            $last = $request->getLastRequest();
            $info = $last['info'];
            if ($info['http_code'] != '302') {
                $this->setError("COULDNOTGETACCESSTOKEN", "Unexpected response from the OAuth service, unable to authorize.");
                return false;
            }

            $url = $info['redirect_url'];
            if (strpos($url, '?') === FALSE) {
                $this->setError("COULDNOTGETACCESSTOKEN", "Unexpected response from the OAuth service, unable to authorize.");
                return false;
            }

            list($host, $url) = explode('?', $url, 2);
            parse_str($url, $values);
            if (!isset($values['oauth_verifier']) || strlen($values['oauth_verifier']) < 2) {
                $this->setError("COULDNOTFINDVERIFIER", "Unexpected response from OAuth service, unable to complete authorization.");
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
            if (!$accessToken) {
                $this->setError("COULDNOTGETACCESSTOKENNULL", "Unable to retrieve access token, please try again.");
                return false;

            }
            $this->setAccessToken($accessToken->getAccessToken())->setAccessTokenSecret($accessToken->getAccessTokenSecret());
            $this->_oaData['accessToken'] = $accessToken;
            return $this;
        } catch (Exception $e) {
            // Add error
            $this->setError("COULDNOTLOGIN", "Error while authorizing. " . $e->getMessage());
            return false;
        }
    }
}
