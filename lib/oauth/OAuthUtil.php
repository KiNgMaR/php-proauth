<?php


class OAuthException extends Exception
{
	protected $http_response_code;

	/**
	 * Standard constructor. The http_response_code should be set
	 * according to section 10 of the OAuth Core specs.
	 * @param int http_response_code
	 **/
	public function __construct($error_msg, $http_response_code = 500)
	{
		parent::__construct($error_msg);

		$this->http_response_code = $http_response_code;
	}

	/**
	 * Sends the HTTP response header. Does *not* output the error description.
	 * Use getMessage() to get the error message.
	 **/
	public function sendHttpResponseHeader()
	{
		$response_codes = array(400 => 'Bad Request',
			401 => 'Authorization Required',
			500 => 'Internal Server Error');

		$response_descr = OAuthUtil::getIfSet($response_codes, $this->http_response_code);

		if(empty($response_descr))
		{
			throw new Exception('OAuthException with unsupported HTTP response code "' . $this->http_response_code . '"');
		}

		header('HTTP/1.0 ' . $this->http_response_code . ' ' . $response_descr);
	}
}


class OAuthUtil
{
	/**
	 * Returns $default if $arr[$key] is unset.
	 **/
	static public function getIfSet(&$arr, $key, $default = NULL)
	{
		if(isset($arr) && is_array($arr) && !empty($arr[$key]))
		{
			return $arr[$key];
		}

		return $default;
	}

	/**
	 * Encodes the given string (or array!) according to RFC 3986, as defined
	 * by the OAuth Core specs section 5.1.
	 **/
	static public function urlEncode($input)
	{
		if(is_array($input))
		{
			return array_map(array(self, 'urlEncode'), $input);
		}
		elseif(is_scalar($input))
		{
			if(defined('PHP_VERSION_ID') && PHP_VERSION_ID >= 50300)
			{
				// rawurlencode is RFC 3986 compliant, starting with PHP 5.3.0...
				return rawurlencode($input);
			}
			else
			{
				return str_replace(array('+', '%7E'), array('%20', '~'), rawurlencode($input));
			}
		}
		else
		{
			throw new OAuthException('Unsupported parameter type for ' . __FUNCTION__);
		}
	}

	/**
	 * Works similarly to http_build_query, but uses our custom URL encoding method.
	 **/
	static public function joinParametersMap(array $params)
	{
		$str = '';

		foreach($params as $key => $value)
		{
			// For each parameter, the name is separated from the corresponding value by an '=' character (ASCII code 61)
			// Each name-value pair is separated by an '&' character (ASCII code 38)

			if(!empty($str)) $str .= '&';
			$str .= self::urlEncode($key) . '=' . self::urlEncode($value);
		}

		return $str;
	}

	/**
	 * URL decodes the given string (or array!)...
	 **/
	static public function urlDecode($input)
	{
		if(is_array($input))
		{
			return array_map(array(self, 'urlDecode'), $input);
		}
		elseif(is_scalar($input))
		{
			return rawurldecode($input);
		}
		else
		{
			throw new OAuthException('Unsupported parameter type for ' . __FUNCTION__);
		}
	}

	/**
	 * Returns true if a parameter with the name $name is part of the OAuth specs.
	 **/
	static public function isKnownOAuthParameter($name)
	{
		$names = array('oauth_consumer_key', 'oauth_token', 'oauth_signature_method', 'oauth_signature', 'oauth_timestamp', 'oauth_nonce', 'oauth_version', 'oauth_callback');

		return in_array($name, $names, true);
	}

	/**
	 * Determines and returns the value of the HTTP Authorization header
	 * that has been sent with the current page request.
	 **/
	static public function getPageRequestAuthorizationHeader()
	{
		$auth_str = self::getIfSet($_SERVER, 'HTTP_AUTHORIZATION', '');

		if(empty($auth_str))
		{
			if(function_exists('apache_request_headers'))
			{
				$headers = apache_request_headers();

				$auth_str = self::getIfSet($headers, 'Authorization');
			}
		}

		return $auth_str;
	}

	/**
	 * Parses an HTTP Authorization header according to section 5.4.1 of
	 * the OAuth Core specs.
	 * @param header_string string e.g. 'OAuth realm="...", oauth_token="..." ...'
	 * @return array An array with all the oauth parameters (unencoded!) and the realm string, or false if the header is not an OAuth header.
	 **/
	static public function parseHttpAuthorizationHeader($header_string)
	{
		if(!preg_match('~^OAuth\s+(.+)$~s', $header_string, $match))
		{
			return false;
		}

		$params = array();

		// Parameters are separated by a comma character (ASCII code 44) and OPTIONAL linear whitespace per RFC2617:
		$pairs = preg_split('~,\s*~', $match[1]);

		foreach($pairs as $pair)
		{
			$syntax_error = true;

			// For each parameter, the name is immediately followed by an '=' character (ASCII code 61),
			// a '"' character (ASCII code 34), the parameter value (MAY be empty),
			// and another '"' character (ASCII code 34).
			$pair = explode('=', $pair, 2);

			if(count($pair) == 2)
			{
				$name = trim($pair[0]);
				$value = trim($pair[1]);

				if(strlen($value) >= 2 && $value[0] == '"' && substr($value, -1) == '"')
				{
					// Parameter names and values are encoded per Parameter Encoding.
					$name = self::urlDecode($name);
					$value = self::urlDecode(substr($value, 1, -1));

					if(strpos($value, '"') === false && (self::isKnownOAuthParameter($name) || $name == 'realm'))
					{
						// The OPTIONAL realm parameter is added and interpreted per RFC2617.
						$syntax_error = false;
						$params[$name] = $value;
					}
				}
			}

			if($syntax_error)
			{
				throw new OAuthException('Syntax or name error while parsing Authorization header.');
			}
		}

		if(count($params) == 0)
		{
			throw new OAuthException('Woops, an Authorization header without any parameters?');
		}

		return $params;
	}

	/**
	 * Localizes the given URL according to section 9.1.2 of the OAuth Core specs.
	 **/
	static public function normalizeRequestURL($url)
	{
		if(!filter_var($url, FILTER_VALIDATE_URL))
		{
			throw new OAuthException('Attempted to normalize an invalid URL: "' . $url . '"');
		}

		$parts = parse_url($url);

		$scheme = strtolower($parts['scheme']);
		$default_port = ($scheme == 'https' ? 443 : 80);

		$host = strtolower($parts['host']);
		$port = (int)self::getIfSet($parts, 'port', $default_port);

		// Note that HTTP does not allow empty absolute paths, so the URL
		// 'http://example.com' is equivalent to 'http://example.com/' and
		// should be treated as such for the purposes of OAuth signing (rfc2616, section 3.2.1)!
		$path = self::getIfSet($parts, 'path', '/');

		if($port != $default_port)
		{
			$host .= ':' . $port;
		}

		return $scheme . '://' . $host . $path;
	}

	/**
	 * Returns a random string consisting of letters and numbers
	 **/
	static public function randomString($length)
	{
		$s = '';
		for($i = 0; $i < $length; $i++)
		{
			switch(mt_rand(0, mt_rand(3, 4)))
			{
				case $i % 2:
					$s .= mt_rand(0, 9); break;
				case ($i + 1) % 2:
					$s .= chr(mt_rand(65, 90)); break;
				default:
					$s .= chr(mt_rand(97, 122));
			}
		}
		return $s;
	}
}


class OAuthToken
{
	protected $token;
	protected $secret;
	protected $additional_params = array();

	public function __construct($token, $secret)
	{
		$this->token = $token;
		$this->secret = $secret;
	}

	public function getToken() { return $token; }
	public function getSecret() { return $secret; }

	public function setAdditionalParam($name, $value)
	{
		if($name != 'oauth_token' && $name != 'oauth_secret')
		{
			$this->additional_params[$name] = $value;
		}
	}

	public function __toString()
	{
		$params = array('oauth_token' => $this->token,
			'oauth_secret' => $this->secret);

		$params = array_merge($params, $this->additional_params);

		return OAuthUtil::joinParametersMap($params);
	}
}

