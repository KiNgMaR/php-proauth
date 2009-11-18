<?php


class OAuthException extends Exception
{
	protected $http_response_code;

	public function __construct($error_msg, $http_response_code = 500)
	{
		parent::__construct($error_msg);

		$this->http_response_code = $http_response_code;
	}

	/**
	* Sends the HTTP response header, ideally as per OAuth Core specs
	* section 10.
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
	static public function getIfSet($arr, $key, $default = NULL)
	{
		if(is_array($arr) && !empty($arr[$key]))
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
	 * URL decodes the given string (or array!)...
	 **/
	static public function urlDecode($str)
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
		$names = array('oauth_consumer_key', 'oauth_signature_method', 'oauth_signature', 'oauth_timestamp', 'oauth_nonce', 'oauth_version', 'oauth_callback');

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
		if(!preg_match('~^OAuth\s+(.+)~', $header_string, $match))
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

					if(self::isKnownOAuthParameter($name) || $name == 'realm')
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

		$url = parse_url($url);

		$scheme = strtolower($parts['scheme']);
		$default_port = ($scheme == 'https' ? 443 : 80);

		$host = strtolower($parts['host']);
		$port = (int)self::getIfSet($parts, 'port', $default_port);

		$path = self::getIfSet($parts, 'path', '/');

		if($port != $default_port)
		{
			$host .= ':' . $port;
		}

		return $scheme . '://' . $host . $path;
	}
}
