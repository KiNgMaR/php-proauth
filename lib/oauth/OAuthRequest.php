<?php

/**
 * Class that wraps a request to an OAuth enabled API...
 * Will be used by OAuth clients/consumers and servers.
 **/
class OAuthRequest
{
	protected $http_method;
	protected $request_url;

	protected $params_get = array();
	protected $params_post = array();
	protected $params_oauth = array();

	protected $realm = '';

	/**
	 * Do not allow this class to be instantiated directly
	 * You will have to use one of OAuthServerRequest/OAuthClientRequest classes.
	 **/
	protected function __construct()
	{
	}

	/**
	 * Returns the signature base string, as defined by section 9.1 of the OAuth Core specs.
	 **/
	public function getSignatureBaseString()
	{
		$parts = array(
			strtoupper($this->http_method),
			OAuthUtil::normalizeRequestURL($this->request_url),
			$this->getSignableParametersString()
		);

		$parts = OAuthUtil::urlEncode($parts);

		return implode('&', $parts);
	}

	/**
	 * Returns a normalized string of all signable parameters, as defined
	 * by section 9.1.1 of the OAuth Core specs.
	 **/
	protected function getSignableParametersString()
	{
		$params = array_merge($this->params_oauth, $this->params_get, $this->params_post);

		unset($params['oauth_signature']);

		// parameters are sorted by name, using lexicographical byte value ordering:
		uksort($params, 'strcmp');

		// again: we do not support multiple parameters with the same name!

		return OAuthUtil::joinParametersMap($params);
	}

	/**
	 * Returns the OAuth protocol version this request uses.
	 **/
	public function getOAuthVersion()
	{
		return OAuthUtil::getIfSet($this->params_oauth, 'oauth_version', '1.0');
	}

	/**
	 * Returns the consumer key or false if none is set.
	 **/
	public function getConsumerKey()
	{
		return OAuthUtil::getIfSet($this->params_oauth, 'oauth_consumer_key', false);
	}

	/**
	 * Fills out the nonce and timestamp variables and returns true if both are non-empty.
	 **/
	public function getNonceAndTimeStamp(&$nonce, &$timestamp)
	{
		$nonce = OAuthUtil::getIfSet($this->params_oauth, 'oauth_nonce', false);
		$timestamp = OAuthUtil::getIfSet($this->params_oauth, 'oauth_timestamp', false);

		return (!empty($nonce) && !empty($timestamp));
	}

	/**
	 * Returns the signature method parameter's value or an empty string.
	 **/
	public function getSignatureMethod()
	{
		return OAuthUtil::getIfSet($this->params_oauth, 'oauth_signature_method', '');
	}

	/**
	 * Returns the signature parameter's value or an empty string.
	 **/
	public function getSignatureParameter()
	{
		return OAuthUtil::getIfSet($this->params_oauth, 'oauth_signature', '');
	}

	/**
	 * Gets the realm value from/for the Authorization header.
	 **/
	public function getRealm()
	{
		return $this->realm;
	}

	/**
	 * Sets the realm value for the Authorization header.
	 **/
	public function setRealm($new_realm)
	{
		$this->realm = $new_realm;
	}

/*	public function getSignature(OAuthSignatureMethod $method)
	{
		
	}*/
}
