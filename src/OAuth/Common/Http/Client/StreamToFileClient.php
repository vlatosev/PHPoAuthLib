<?php

namespace OAuth\Common\Http\Client;

use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\UriInterface;

/**
 * Client implementation for streams/file_get_contents
 */
class StreamToFileClient extends StreamClient
{
    protected $file;

    public function setFile($file)
    {
        $this->file = $file;
    }

    /**
     * Any implementing HTTP providers should send a request to the provided endpoint with the parameters.
     * They should return, in string form, the response body and throw an exception on error.
     *
     * @param UriInterface $endpoint
     * @param mixed        $requestBody
     * @param array        $extraHeaders
     * @param string       $method
     *
     * @return string
     *
     * @throws TokenResponseException
     * @throws \InvalidArgumentException
     */
    public function retrieveResponse(
        UriInterface $endpoint,
        $requestBody,
        array $extraHeaders = array(),
        $method = 'POST'
    ) {
        // Normalize method name
        $method = strtoupper($method);

        $this->normalizeHeaders($extraHeaders);

        if ($method === 'GET' && !empty($requestBody)) {
            throw new \InvalidArgumentException('No body expected for "GET" request.');
        }

        if (!isset($extraHeaders['Content-type']) && $method === 'POST' && is_array($requestBody)) {
            $extraHeaders['Content-type'] = 'Content-type: application/x-www-form-urlencoded';
        }

        $extraHeaders['Host']       = 'Host: '.$endpoint->getHost();
        $extraHeaders['Connection'] = 'Connection: close';

        if (is_array($requestBody)) {
            $requestBody = http_build_query($requestBody, '', '&');
        }
        $extraHeaders['Content-length'] = 'Content-length: '.strlen($requestBody);

        $context = $this->generateStreamContext($requestBody, $extraHeaders, $method);

        $level = error_reporting(0);
        if(is_resource($this->file))
        {
            $response = '';
            $absuri = $endpoint->getAbsoluteUri();
            $attach = fopen($absuri, 'rb', null, $context);
            stream_copy_to_stream($attach, $this->file);
        }
        else
        {
            $response = file_get_contents($endpoint->getAbsoluteUri(), false, $context);
        }
        error_reporting($level);
        if (false === $response) {
            $lastError = error_get_last();
            if (is_null($lastError)) {
                throw new TokenResponseException('Failed to request resource.');
            }
            throw new TokenResponseException($lastError['message']);
        }

        return $response;
    }
}
