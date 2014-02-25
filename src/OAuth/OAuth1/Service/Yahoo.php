<?php

namespace OAuth\OAuth1\Service;

use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Token\TokenInterface;
use OAuth\OAuth1\Service\AbstractService;
use OAuth\OAuth1\Token\StdOAuth1Token;

class Yahoo extends AbstractService
{
  const YAHOO_MAIL_SOAP_WSDL = 'http://mail.yahooapis.com/ws/mail/v1.1/wsdl';

  /**
   * @return Uri
   */
  public function getMailAPIEndpoint()
  {
    return new Uri('http://mail.yahooapis.com/ws/mail/v1.1/soap');
  }

  /**
   * {@inheritdoc}
   */
  public function getAccessTokenEndpoint()
  {
    return new Uri('https://api.login.yahoo.com/oauth/v2/get_token');
  }

  /**
   * {@inheritdoc}
   */
  public function getAuthorizationEndpoint()
  {
    return new Uri('https://api.login.yahoo.com/oauth/v2/request_auth');
  }

  /**
   * {@inheritdoc}
   */
  public function getRequestTokenEndpoint()
  {
    return new Uri('https://api.login.yahoo.com/oauth/v2/get_request_token');
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
    $token = new StdOAuth1Token();
    $token->setRequestToken($data['oauth_token']);
    $token->setRequestTokenSecret($data['oauth_token_secret']);
    $token->setAccessToken($data['oauth_token']);
    $token->setAccessTokenSecret($data['oauth_token_secret']);
    $token->setEndOfLife(time() + intval($data['oauth_expires_in']));
    $token->setRefreshToken(isset($data['oauth_session_handle']) ? $data['oauth_session_handle'] : null);
    unset($data['oauth_token'], $data['oauth_token_secret'], $data['oauth_session_handle']);
    $data = isset($data['oauth_authorization_expires_in']) ? array_merge($data, array('refresh_end_of_life' => (time() + intval($data['oauth_authorization_expires_in'])))) : $data;
    $token->setExtraParams($data);
    return $token;
  }

  /**
   * {@inheritdoc}
   */
  protected function buildAuthorizationHeaderForAPIRequest(
    $method,
    UriInterface $uri,
    TokenInterface $token,
    $bodyParams = null
  ) {
    $this->signature->setTokenSecret($token->getAccessTokenSecret());
    $parameters = $this->getBasicAuthorizationHeaderInfo();
    if (isset($parameters['oauth_callback'])) {
      unset($parameters['oauth_callback']);
    }

    $parameters = array_merge($parameters, array('oauth_token' => $token->getAccessToken()));

    $mergedParams = (is_array($bodyParams)) ? array_merge($parameters, $bodyParams) : $parameters;

    $mergedParams['oauth_signature'] = $this->signature->getSignature($uri, $mergedParams, $method);

    $authorizationHeader = 'OAuth ';
    $delimiter = '';

    foreach ($mergedParams as $key => $value) {
      $authorizationHeader .= $delimiter . rawurlencode($key) . '="' . rawurlencode($value) . '"';
      $delimiter = ', ';
    }

    return $authorizationHeader;
  }

  public function refreshAccessToken(TokenInterface $token)
  {
    $data = $token->getExtraParams();
    $endlife = isset($data['refresh_end_of_life']) ? $data['refresh_end_of_life'] : time() + 3600;
    if($endlife < time())
    {
      $this->storage->clearToken($this->service());
      throw new TokenResponseException("Refresh token expired");
    }
    $refreshToken = $token->getRefreshToken();
    $parameters = array('oauth_session_handle' => $token->getRefreshToken());
    $responseBody = $this->request($this->getAccessTokenEndpoint(), 'POST', $parameters);
    $token = $this->parseAccessTokenResponse($responseBody);
    $this->storage->storeAccessToken($this->service(), $token);

    return $token;

  }

  public function getSoapClient(\OAuth\OAuth1\Token\TokenInterface $token, $yahoo_service)
  {
    switch($yahoo_service)
    {
      case 'mail':
        $wsdl     = self::YAHOO_MAIL_SOAP_WSDL;
        $endPoint = $this->getMailAPIEndpoint();
        break;
      default:
        $wsdl = '';
        $endPoint = '';
        break;
    }

    $oauthHeaderForSoap  = $this->buildAuthorizationHeaderForAPIRequest('POST', $endPoint, $token);
    $oauthHeaderForSoap = "Authorization: $oauthHeaderForSoap";
    //$oauthHeaderForSoap = $this->soapHeader;
    try{

      $soapClient = new \SoapClient($wsdl, array(
        'stream_context' => stream_context_create(array('http' => array( 'header' => "$oauthHeaderForSoap\n"))),
        'trace'          => 1,
        'location'       => $endPoint->getAbsoluteUri()
      ));
    }catch (Exception $e){
      $soapClient = null;
    }
    return array(
      'soap_client' => $soapClient,
      'service'     => $this
    );
  }

  public function requestFile($urlcall, $file)
  {
    $this->httpClient->setFile($file);
    $this->request($urlcall);
  }
}