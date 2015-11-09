<?php

namespace OAuth\Common\Http\Client;

/**
 * Abstract HTTP client
 */
abstract class AbstractClient implements ClientInterface
{
    /**
     * @var string The user agent string passed to services
     */
    protected $userAgent;

    /**
     * @var int The maximum number of redirects
     */
    protected $maxRedirects = 5;

    /**
     * @var int The maximum timeout
     */
    protected $timeout = 15;

    protected $lastRequest = null;

    /**
     * Creates instance
     *
     * @param string $userAgent The UA string the client will use
     */
    public function __construct($userAgent = 'PHPoAuthLib')
    {
        $this->userAgent = $userAgent;
    }

    /**
     * @param int $redirects Maximum redirects for client
     *
     * @return ClientInterface
     */
    public function setMaxRedirects($redirects)
    {
        $this->maxRedirects = $redirects;

        return $this;
    }

    /**
     * @param int $timeout Request timeout time for client in seconds
     *
     * @return ClientInterface
     */
    public function setTimeout($timeout)
    {
        $this->timeout = $timeout;

        return $this;
    }

    /**
     * @param array $headers
     */
    public function normalizeHeaders(&$headers)
    {
        // Normalize headers
        array_walk(
            $headers,
            function (&$val, &$key) {
                if (!is_numeric($key)) {
                    $key = ucfirst(strtolower($key)) . ": ";
                } else {
                    $key = "";
                }
                $val = $key . $val;
            }
        );
    }

    public function parseHeaders($headers)
    {
        $parsed = array();
        if (!is_array($headers)) {
            throw new \InvalidArgumentException("Expected array for processing");
        }

        foreach ($headers as $h) {
            if (strpos($h, ":") === FALSE) {
                continue;
            }

            list($k, $v) = explode(":", $h, 2);
            $k = strtolower($k);
            if (isset($parsed[$k])) {
                $parsed[$k] = (array)$parsed[$k];
                $parsed[$k][] = trim($v);
            } else {
                $parsed[$k] = $v;
            }
        }
        return $parsed;
    }

    public function getLastRequest($part = null)
    {
        if ($this->lastRequest && $part) {
            if (!is_string($part) || !in_array($part, array('body', 'headers', 'error', 'info'))) {
                throw new \InvalidArgumentException("Specified part not available");
            }
            return isset($this->lastRequest[$part]) ? $this->lastRequest[$part] : null;
        }

        return $this->lastRequest;
    }
}
