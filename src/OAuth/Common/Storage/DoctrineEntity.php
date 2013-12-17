<?php

namespace OAuth\Common\Storage;

class DoctrineEntity implements TokenStorageInterface
{
  public function __construct()
  {
  }

  /**
   * {@inheritDoc}
   */
  public function retrieveAccessToken($service)
  {
    throw new TokenNotFoundException('Token not found in session, are you sure you stored it?');
  }

  /**
   * {@inheritDoc}
   */
  public function storeAccessToken($service, TokenInterface $token)
  {
    // allow chaining
    return $this;
  }

  /**
   * {@inheritDoc}
   */
  public function hasAccessToken($service)
  {
    // get from db-table
    $tokens = $this->session->get($this->sessionVariableName);

    return is_array($tokens)
    && isset($tokens[$service])
    && $tokens[$service] instanceof TokenInterface;
  }

  /**
   * {@inheritDoc}
   */
  public function clearToken($service)
  {
    // get previously saved tokens
    $tokens = $this->session->get($this->sessionVariableName);

    if (is_array($tokens) && array_key_exists($service, $tokens)) {
      unset($tokens[$service]);

      // Replace the stored tokens array
      $this->session->set($this->sessionVariableName, $tokens);
    }

    // allow chaining
    return $this;
  }

  /**
   * {@inheritDoc}
   */
  public function clearAllTokens()
  {
    $this->session->remove($this->sessionVariableName);

    // allow chaining
    return $this;
  }

  /**
   * @return Session
   */
  public function getSession()
  {
    return $this->session;
  }
}
