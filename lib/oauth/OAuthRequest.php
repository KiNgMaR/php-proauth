<?php

class OAuthRequest
{
	protected $http_method;
	protected $request_url;

	protected $params_get;
	protected $params_post;
	protected $params_oauth;

	private __construct() {}

	public createFromPageRequest()
	{
		$new_req = new OAuthRequest();

		// Determine HTTP method...
		$new_req->http_method = OAuthUtils::getIfSet($_SERVER, 'REQUEST_METHOD');

		if(empty($new_req->http_method))
		{
			// :TODO: find out if this actually happens and how bad the fallback is.
			$new_req->http_method = (count($_POST) > 0 ? 'POST' : 'GET');
		}


		// Determine request URL:
		$host = OAuthUtils::getIfSet($_SERVER, 'HTTP_HOST');

		if(empty($host))
		{
			throw new OAuthException('The requesting client did not send the HTTP Host header which is required by this implementation.');
		}

		$scheme = (OAuthUtils::getIfSet($_SERVER, 'HTTPS', 'off') === 'on' ? 'https' : 'http');

		$port = (int)$_SERVER['SERVER_PORT'];

		$new_req->request_url = $scheme . '://' . $host .
			($port == ($scheme == 'https' ?  443 : 80) ? '' : ':' . $port) .
			$_SERVER['REQUEST_URI'];


		// extract oauth parameters from the Authorization
		// HTTP header. If present, these take precedence over
		// GET and POST parameters.
		$header_parameters = OAuthUtils::getPageRequestAuthorizationHeader();

		if(!empty($header_parameters))
		{
			$header_parameters = OAuthUtils::parseHttpAuthorizationHeader($header_parameters);
			$realm = '';

			if(is_array($header_parameters) && count($header_parameters) > 0)
			{
				$realm = OAuthUtils::getIfSet($header_parameters, 'realm');

				$new_req->params_oauth = $header_parameters;
			}

			/* :TODO: Check and/or store the realm parameter here... */
		}

		// The next paragraphs implement section 5.2 from the OAuth Core specs.
		// ... at least mostly... :TODO: we do not care about the Content-Type (application/x-www-form-urlencoded)
		// and we rely on PHP to parse the $_POST and $_GET parameters for us.
		// This *could* break in some weird cases, where URL decoding is done very strangely...
		// ... but that's okay for now!

		// extract POST parameters...
		$new_req->params_post = array();

		foreach($_POST as $key => $value)
		{
			if(OAuthUtils::isKnownOAuthParameter($key))
			{
				if(!isset($new_req->params_oauth[$key]))
				{
					$new_req->params_oauth[$key] = $value;
					unset($_POST[$key]);
				}
				else
				{
					throw new OAuthException('You cannot specify the "' . $key . '" parameter multiple times.');
				}
			}
			else
			{
				$new_req->params_post[$key] = $value;
			}
		}

		// extract GET parameters...
		$new_req->params_get = array();

		foreach($_GET as $key => $value)
		{
			if(OAuthUtils::isKnownOAuthParameter($key))
			{
				if(!isset($new_req->params_oauth[$key]))
				{
					$new_req->params_oauth[$key] = $value;
					unset($_GET[$key]);
				}
				else
				{
					throw new OAuthException('You cannot specify the "' . $key . '" parameter multiple times.');
				}
			}
			else
			{
				if(isset($new_req->params_post[$key]))
				{
					throw new OAuthException('We do not support GET and POST parameters with the same name.');
				}

				$new_req->params_get[$key] = $value;
			}
		}

		// phew...
		return $new_req;
	}

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
