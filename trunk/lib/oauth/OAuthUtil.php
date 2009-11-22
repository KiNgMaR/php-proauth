<?php


class OAuthException extends Exception
{
	protected $http_response_code;
	protected $oauth_problem, $oauth_problem_extra_info;

	/**
	 * Standard constructor. The http_response_code should be set
	 * according to section 10 of the OAuth Core specs.
	 * @param int http_response_code
	 **/
	public function __construct($error_msg, $http_response_code = 500, $oauth_problem = '', array $oauth_problem_extra_info = NULL)
	{
		parent::__construct($error_msg);

		$this->http_response_code = $http_response_code;
		$this->oauth_problem = $oauth_problem;
		$this->oauth_problem_descr = $oauth_problem_extra_info;
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

	/**
	 * Returns a string that follows the guidelines at
	 * http://oauth.pbworks.com/ProblemReporting if an oauth_problem
	 * has been specified in the constructor or an empty string otherwise.
	 * The returned string can be used in a WWW-Authenticate header, or as
	 * the body part of the response. It must not be HTML encoded or otherwise
	 * escpaed.
	 **/
	public function getOAuthProblemString()
	{
		if(empty($this->oauth_problem))
		{
			return '';
		}

		$params = array('oauth_problem' => $this->oauth_problem,
			'oauth_problem_advice' => $this->getMessage());

		if(is_array($this->oauth_problem_extra_info))
		{
			$params = array_merge($params, $this->oauth_problem_extra_info);
		}

		return OAuthUtil::joinParametersMap($params);
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
			// we use urldecode (instead of rawurldecode) here, because section 3.4.1.3.1. of the hammer-draft says:
			// <quote>While the encoding rules specified in this specification for the purpose of constructing the
			// signature base string exclude the use of a + character (ASCII code 43) to represent an encoded
			// space character (ASCII code 32), this practice is widely used in application/x-www-form-urlencoded
			// encoded values, and MUST be properly decoded.</quote>
			return urldecode($input);
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
		$names = array('oauth_consumer_key', 'oauth_token', 'oauth_signature_method', 'oauth_signature',
			'oauth_timestamp', 'oauth_nonce', 'oauth_version', 'oauth_callback', 'oauth_error_in_response_body');

		return in_array($name, $names, true);
	}

	/**
	 * Returns an array of all HTTP request headers. The key names will
	 * be all lowercase, for RFC 2612 section 4.2 requires
	 * them to be treated case-insensitively.
	 **/
	static public function getPageRequestHeaders()
	{
		$headers = array();

		if(function_exists('apache_request_headers'))
		{
			$temp_headers = apache_request_headers();

			foreach($temp_headers as $key => $value) { $headers[strtolower($key)] = $value; }
		}
		else
		{
			foreach($_SERVER as $key => $value)
			{
				if(strpos($key, 'HTTP_') === 0)
				{
					// transform e.g. "HTTP_USER_AGENT" into "user-agent":
					$header_name = substr($key, 5);
					$header_name = strtolower($header_name);
					$header_name = strtr($header_name, '_', '-');

					$headers[$header_name] = $value;
				}
			}
		}

		return $headers;
	}

	/**
	 * Parses an HTTP Authorization header according to section 5.4.1 of
	 * the OAuth Core specs.
	 * @param header_string string e.g. 'OAuth realm="...", oauth_token="..." ...'
	 * @return array An array with all the oauth parameters (unencoded!) and the realm string, or false if the header is not an OAuth header.
	 **/
	static public function parseHttpAuthorizationHeader($header_string)
	{
		// The extension auth-scheme (as defined by RFC2617) is "OAuth" and is case-insensitive.
		if(!preg_match('~^OAuth\s+(.+)$~si', $header_string, $match))
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

	/**
	 * Validates the given URL. Returns the validated URL.
	 * It is advised to always use the return value.
	 **/
	static public function validateCallbackURL($url)
	{
		if(empty($url))
		{
			return '';
		}

		if($url === 'oob')
		{
			// "out-of-band configuration", such as a desktop client,
			// that doesn't have a http:// redir URL.
			return $url;
		}

		if(filter_var($url, FILTER_VALIDATE_URL))
		{
			$parts = parse_url($url);
			$scheme = strtolower($parts['scheme']);

			if($scheme == 'http' || $scheme == 'https')
			{
				return $url;
			}
		}

		throw new OAuthException('An invalid callback URL has been used.', 401);
	}

	/**
	 * Splits the headers off the body of an HTTP response. Discards the first
	 * line of the headers (the one with the status code). Splits the headers
	 * into the headers array.
	 **/
	static public function splitHttpResponse($response, array &$headers, &$body)
	{
		// some boring checks, etc:
		$headers_end = strpos($response, "\r\n\r\n");

		if($headers_end === false)
		{
			$headers_end = strpos($response, "\n\n");
		}

		if($headers_end === false)
		{
			// response without body...
			$headers_end = strlen($response);
		}

		// parse and verify the first line:
		if(!preg_match('~^HTTP/(\d\.\d)\s+(\d+)\s+([ \w]+)\r?\n~i', $response, $match))
		{
			throw new OAuthException('Failed to parse HTTP response: No HTTP/ found.');
		}
		list(, $http_version, $response_code, $response_descr) = $match;

		// parse the headers...
		// http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2
		// the link is just for reference, we do not actually implement
		// all of the specs :(
		$header_str = trim(substr($response, 0, $headers_end));
		$headers = array();

		$lines = preg_split('~\r?\n~', $header_str);
		array_shift($lines); // remove the first line.
		$header_name = '';
		foreach($lines as $line)
		{
			if(preg_match('~^[ \t]+(.+)~', $line, $match))
			{
				if(empty($header_name))
				{
					throw new OAuthException('Error while parsing HTTP response headers: Continuated header without name.');
				}
				$headers[$header_name] .= ' ' . $match[1];
			}
			elseif(preg_match('~^(.+?):\s*(.*?)$~', $line, $match))
			{
				$header_name = strtolower($match[1]);
				$headers[$header_name] = trim($match[2]);
			}
			else
			{
				throw new OAuthException('Error while parsing HTTP response headers: Weird-looking/unsupported header line.');
			}
		}

		// assign the body content:
		$body = ltrim(substr($response, $headers_end));
	}
}


class OAuthConsumer
{
	protected $key;
	protected $secret;

	/**
	 * @param key string
	 * @param secret string
	 **/
	public function __construct($key, $secret)
	{
		if(!is_string($key) || !is_string($secret))
		{
			throw new OAuthException('Consumer key and secret MUST be string values.');
		}

		$this->key = $key;
		$this->secret = $secret;
	}

	public function getKey() { return $key; }
	public function getSecret() { return $secret; }
}


class OAuthToken
{
	protected $token;
	protected $secret;
	protected $additional_params = array();

	/**
	 * @param token string
	 * @param secret string
	 **/
	public function __construct($token, $secret)
	{
		if(!is_string($token) || !is_string($secret))
		{
			throw new OAuthException('Token and secret MUST be string values.');
		}

		$this->token = $token;
		$this->secret = $secret;
	}

	public function getToken() { return $token; }
	public function getSecret() { return $secret; }

	/**
	 * Sets an additional parameter.
	 * Mainly useful in combination with __toString.
	 * Escaping any of the arguments is not necessary.
	 **/
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

		$params = array_merge($this->additional_params, $params);

		return OAuthUtil::joinParametersMap($params);
	}
}

