<?php

/**
 * Class that wraps a request to an OAuth enabled API...
 * Will be used by OAuth clients/consumers and servers.
 **/
class OAuthRequest
{
	protected $http_method;
	protected $request_url;

	protected $params_get;
	protected $params_post;
	protected $params_oauth;

	/**
	 * Do not allow this class to be instantiated directly
	 * You will have to use one of OAuthServerRequest/OAuthClientRequest classes.
	 **/
	protected function __construct() {}

	/**
	 * Returns the signature base string, as defined by section 9.1 of the OAuth Core specs.
	 **/
	public function getSignatureBaseString()
	{
		$parts = array(
			strtoupper($this->http_method),
			OAuthUtils::normalizeRequestURL($this->request_url),
			$this->getSignableParametersString()
		);

		$parts = OAuthUtils::urlEncode($parts);

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

		// urlencode both keys and values:
		$keys = OAuthUtils::urlEncode(array_keys($params));
		$values = OAuthUtils::urlEncode(array_values($params));
		$params = array_combine($keys, $values);

		$str = '';

		foreach($params as $key => $value)
		{
			// For each parameter, the name is separated from the corresponding value by an '=' character (ASCII code 61)
			// Each name-value pair is separated by an '&' character (ASCII code 38)

			if(!empty($str)) $str .= '&';
			$str .= $key . '=' . $value;
		}

		return $str;
	}

	/**
	 * Returns the OAuth protocol version this request uses.
	 **/
	public function getOAuthVersion()
	{
		return OAuthUtils::getIfSet($this->params_oauth, 'oauth_version', '1.0');
	}

	/**
	 * Returns the consumer key or false if none is set.
	 **/
	public function getConsumerKey()
	{
		return OAuthUtils::getIfSet($this->params_oauth, 'oauth_consumer_key', false);
	}

	public function getNonceAndTimeStamp(&$nonce, &$timestamp)
	{
		$nonce = OAuthUtils::getIfSet($this->params_oauth, 'oauth_nonce', false);
		$timestamp = OAuthUtils::getIfSet($this->params_oauth, 'oauth_timestamp', false);

		return (!empty($nonce) && !empty($timestamp));
	}

/*	public function getSignature(OAuthSignatureMethod $method)
	{
		
	}*/
}
