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

namespace OAuth\OAuth1\Service;

use OAuth\OAuth1\Signature\SignatureInterface;
use OAuth\OAuth1\Token\StdOAuth1Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Client\ClientInterface;

/**
 * Defines custom ACS API logic within the OAuth service structure to handle som eof the incongruencies of the ACS API
 *
 * @package OAuth\OAuth1\Service
 */
class Foresee extends AbstractService
{
    /**
     * Default API URI
     * @var string
     */
    const DEFAULT_BASE_API_URI = 'https://portal2.foreseeresults.com/services/';

    /**
     * Standard constructor, adds default base API Uri if not provided
     *
     * @param CredentialsInterface $credentials
     * @param ClientInterface $httpClient
     * @param TokenStorageInterface $storage
     * @param SignatureInterface $signature
     * @param UriInterface|null $baseApiUri
     */
    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        SignatureInterface $signature,
        UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $signature, $baseApiUri);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri(static::DEFAULT_BASE_API_URI);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getRequestTokenEndpoint()
    {
        return new Uri($this->baseApiUri . 'oauth/request_token');
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint($params = null)
    {
        $uri = new Uri($this->baseApiUri . 'oauth/user_authorization');
        if ($params) {
            $uri->setQuery(http_build_query($params));
        }
        return $uri;
    }

    /**
     * {@inheritdoc}
     */
    public function getLoginEndpoint()
    {
        return new Uri($this->baseApiUri . 'login');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri($this->baseApiUri . 'oauth/access_token');
    }

    /**
     * Retrieves an instance of the last response object from the HTTP Client library
     *
     * @return mixed
     */
    public function getLastRequest()
    {
        $last = $this->httpClient->getLastRequest();

        return $last;
    }

    /**
     * Entry point to start the request for the REQUEST TOKEN
     *
     * @return \OAuth\Common\Token\TokenInterface|\OAuth\OAuth1\Token\TokenInterface
     */
    public function requestRequestToken()
    {
        $token = parent::requestRequestToken();
        return $token;
    }

    /**
     * Entry point ot start the request for the ACCESS TOKEN
     *
     * @param string $token
     * @param string $verifier
     * @param null $tokenSecret
     * @return StdOAuth1Token|\OAuth\OAuth1\Token\TokenInterface|string
     * @throws TokenResponseException
     */
    public function requestAccessToken($token, $verifier, $tokenSecret = null)
    {
        if (is_null($tokenSecret)) {
            $storedRequestToken = $this->storage->retrieveAccessToken($this->service());
            $tokenSecret = $storedRequestToken->getRequestTokenSecret();
        }
        $this->signature->setTokenSecret($tokenSecret);

        $authorizationHeader = array(
            'Authorization' => $this->buildAuthorizationHeaderForAPIRequest(
                'GET',
                $this->getAccessTokenEndpoint(),
                $this->storage->retrieveAccessToken($this->service()),
                array('oauth_verifier' => $verifier)
            )
        );

        $headers = array_merge($authorizationHeader, $this->getExtraOAuthHeaders());

        $responseBody = $this->httpClient->retrieveResponse($this->getAccessTokenEndpoint(), null, $headers, "GET");

        $token = $this->parseAccessTokenResponse($responseBody);
        $this->setAccessToken($token);
        return $token;
    }

    /**
     * Sets internal access token
     * @param $token
     * @return $this
     */
    public function setAccessToken($token)
    {
        $this->storage->storeAccessToken($this->service(), $token);

        return $this;
    }

    /**
     * Creates an access token instance after parsing the supplied data
     * @param $data
     * @return StdOAuth1Token
     */
    public function createAccessToken($data)
    {
        $token = new StdOAuth1Token();

        $token->setRequestToken($data['oauth_token']);
        $token->setRequestTokenSecret($data['oauth_token_secret']);
        $token->setAccessToken($data['oauth_token']);
        $token->setAccessTokenSecret($data['oauth_token_secret']);

        $token->setEndOfLife(StdOAuth1Token::EOL_NEVER_EXPIRES);
        unset($data['oauth_token'], $data['oauth_token_secret']);
        $token->setExtraParams($data);

        return $token;
    }

    /**
     * Retrieves the internal access token
     * @return \OAuth\Common\Token\TokenInterface
     */
    public function getAccessToken()
    {
        return $this->storage->retrieveAccessToken($this->service());
    }

    /**
     * {@inheritdoc}
     */
    protected function parseRequestTokenResponse($responseBody)
    {
        parse_str($responseBody, $data);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (!isset($data['oauth_callback_confirmed']) || $data['oauth_callback_confirmed'] !== 'true') {
            throw new TokenResponseException('Error in retrieving token.');
        }

        return $this->parseAccessTokenResponse($responseBody);
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        parse_str($responseBody, $data);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        return $this->createAccessToken($data);
    }
}
