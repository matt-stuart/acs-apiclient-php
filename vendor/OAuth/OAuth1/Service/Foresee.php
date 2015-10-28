<?php

namespace OAuth\OAuth1\Service;

use OAuth\OAuth1\Signature\SignatureInterface;
use OAuth\OAuth1\Token\StdOAuth1Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Client\ClientInterface;

class Foresee extends AbstractService
{
    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        SignatureInterface $signature,
        UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $signature, $baseApiUri);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://portal2.foreseeresults.com/services/');
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

    public function requestRequestToken()
    {
        $token = parent::requestRequestToken();
        $headers = $this->httpClient->getLastRequest('headers');

        return $token;
    }

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

    public function setAccessToken($token)
    {
        $this->storage->storeAccessToken($this->service(), $token);

        return $this;
    }

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
