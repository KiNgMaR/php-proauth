<?php

if(!defined('_OAUTH_LIB_DIR'))
{
	define('_OAUTH_LIB_DIR', dirname(__FILE__) . '/');
}

require_once _OAUTH_LIB_DIR . 'OAuthUtil.php';
require_once _OAUTH_LIB_DIR . 'OAuthRequest.php';
require_once _OAUTH_LIB_DIR . 'OAuthSignature.php';


class OAuthClientBase
{
	protected $consumer;
	protected $token;
	protected $signature_method;

	public function __construct(OAuthConsumer $consumer, OAuthSignatureMethod $signature_method, OAuthToken $token = NULL)
	{
		$this->consumer = $consumer;
		$this->token = $token;
		$this->signature_method = $signature_method;
	}

	/**
	 * returns an OAuthClientRequest instance that can be set up further, as necessary, and then
	 * be submitted.
	 **/
	public function createRequest($url, array $get_params = array(), array $post_params = array())
	{
		$req = new OAuthClientRequest($this->consumer, $this->token, (count($_POST) > 0 ? 'POST' : 'GET'), $url);

		$req->setGetParameters($get_params);
		$req->setPostParameters($post_params);

		return $req;
	}

	/**
	 * @see createRequest
	 **/
	public function createPostRequest($url, array $params = array())
	{
		$req = new OAuthClientRequest($this->consumer, $this->token, 'POST', $url);

		$req->setPostParameters($params);

		return $req;
	}

	/**
	 * @see createRequest
	 **/
	public function createGetRequest($url, array $params = array())
	{
		$req = new OAuthClientRequest($this, 'GET', $url);

		$req->setPostParameters($params);

		return $req;
	}

	/**
	 * Generates and returns a most probably unique nonce with a length of about 27 characters.
	 **/
	public function generateNonce()
	{
		$nonce = uniqid(mt_rand()) . '/' . microtime(true);
		$nonce = base64_encode(sha1($nonce, true));
		$nonce = rtrim($nonce, '=');
		return $nonce;
	}

	/**
	 * Returns the timestamp for the next request.
	 **/
	public function generateTimestamp()
	{
		// following this discussion, we *do* use time(), but
		// rely on Service Providers to follow the
		// "Each nonce is unique per timestamp value" rule.
		// http://groups.google.com/group/oauth/tree/browse_frm/month/2007-10/fba9c641984a63c1
		return time();
		// the protocol has room for improvement here.
	}

	/**
	 * @return OAuthToken
	 **/
	public function getToken() { return $this->token; }

	/**
	 * @return OAuthConsumer
	 **/
	public function getConsumer() { return $this->consumer; }

	/**
	 * @return OAuthSignatureMethod
	 **/
	public function getSignatureMethod() { return $this->signature_method; }
}


class OAuthClientRequest extends OAuthRequest
{
	protected $client;
	protected $signed = false;

	/**
	 * Usually invoked by OAuthClient. It's not recommended to create instances by other means.
	 **/
	public function __construct(OAuthClientBase $client, $http_method, $url)
	{
		parent::__construct();

		if(strcasecmp($http_method, 'POST') && strcasecmp($http_method, 'GET'))
		{
			throw new OAuthException('Unsupported HTTP method "' . $http_method . '" in OAuthClientRequest.');
		}

		$this->client = $client;
		$this->http_method = $http_method;

		// :TODO: handle URLs with GET query parameters.
		// maybe parse them, or throw an error.
		$this->request_url = $url;

		$this->params_oauth['oauth_consumer_key'] = $client->getConsumer()->getKey();

		$token = $this->client->getToken();
		if(!is_null($token))
		{
			$this->params_oauth['oauth_token'] = $token->getToken();
		}
		// we do not add oauth_version=1.0 since it's optional (section 7 of the OAuth Core specs)
	}

	/**
	 * Replaces the existing GET query parameters.
	 **/
	public function setGetParameters(array $new_params)
	{
		$this->params_get = $new_params;
		$this->signed = false;
	}

	/**
	 * Replaces the existing POST parameters.
	 **/
	public function setPostParameters(array $new_params)
	{
		$this->params_post = $new_params;
		$this->signed = false;
	}

	/**
	 * Signs the request. You are asked to immediately send it to the
	 * Service Provider after signing it.
	 **/
	public function sign()
	{
		// :TODO: Only add timestamp+nonce if the signature method requires it.
		$this->params_oauth['oauth_timestamp'] = $this->client->generateTimestamp();
		$this->params_oauth['oauth_nonce'] = $this->client->generateNonce();

		$this->params_oauth['oauth_signature_method'] = $this->client->getSignatureMethod()->getName();
		$this->params_oauth['oauth_signature'] = $this->client->getSignatureMethod()->buildSignature($this,
			$this->client->getConsumer(), $this->client->getToken()); // is this too long? :P

		if(empty($this->params_oauth['oauth_signature']))
		{
			throw new OAuthException('Signing the request completely and utterly failed.');
		}

		$this->signed = true;
	}

	/**
	 * @return bool The current parameters of this request have been signed.
	 **/
	public function isSigned() { return $this->signed; }

	/**
	 * Returns a string like "OAuth realm="...", oauth_token="..".
	 **/
	public function getAuthorizationHeader()
	{
		$result = 'OAuth ';

		$params = array();

		if(!empty($this->realm))
		{
			$params['realm'] = $this->realm;
		}

		// possible problem: if params_oauth contained a value named
		// realm, it would overwrite the real realm. It shouldn't, however.
		$params = array_merge($params, $this->params_oauth);

		foreach($params as $key => $value)
		{
			// we could also spread the header over multiple lines, but some very
			// stupid HTTP servers may not support that, so all goes on one line!
			$result .= OAuthUtil::urlEncode($key) . '="' . OAuthUtil::urlEncode($value) . '", ';
		}

		return rtrim($result, ', ');
	}
}


class OAuthCurlClient extends OAuthClientBase
{
	protected $curl_handle = NULL;

	/**
	 * @see OAuthClientBase::__construct
	 **/
	public function __construct(OAuthConsumer $consumer, OAuthSignatureMethod $signature_method, OAuthToken $token = NULL)
	{
		parent::__construct($consumer, $signature_method, $token);

		$this->curl_handle = curl_init();
		// set all the necessary curl options...
		curl_setopt($this->curl_handle, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($this->curl_handle, CURLOPT_HEADER, true);
		curl_setopt($this->curl_handle, CURLOPT_FAILONERROR, false);

		curl_setopt($this->curl_handle, CURLOPT_CONNECTTIMEOUT, 5);
		curl_setopt($this->curl_handle, CURLOPT_TIMEOUT, 30);

		curl_setopt($this->curl_handle, CURLOPT_USERAGENT, 'php-proauth/1.0 (http://code.google.com/p/php-proauth/) using libcurl');

		// ignore this absolutely stupid warning:
		// CURLOPT_FOLLOWLOCATION cannot be activated when in safe_mode or an open_basedir is set.
		@curl_setopt($this->curl_handle, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($this->curl_handle, CURLOPT_MAXREDIRS, 10);

		// to avoid possibly unwanted SSL problems. :TODO: make this configurable.
		curl_setopt($this->curl_handle, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($this->curl_handle, CURLOPT_SSL_VERIFYHOST, false);

		// enable compression where supported:
		curl_setopt($this->curl_handle, CURLOPT_ENCODING, '');
	}

	/**
	 * Executes the given request using libcurl.
	 * Returns an OAuthClientResponse instance or
	 * throws an OAuchException on errors.
	 **/
	public function executeRequest(OAuthRequest $req)
	{
		$req->sign();

		$http_headers = array();

		// Use the Authorization header for oauth protocol parameters:
		$http_headers[] = 'Authorization: ' . $req->getAuthorizationHeader();

		// Add GET parameters to the URL:
		$url = $req->getRequestUrl(true);
		$url .= '?' . OAuthUtil::joinParametersMap($req->getGetParameters());

		curl_setopt($this->curl_handle, CURLOPT_URL, $url);

		// Add POST parameters, if there are any.
		if($req->getHTTPMethod() == 'POST')
		{
			$http_headers[] = 'Expect:'; // avoid stupid HTTP status code 100.
			$http_headers[] = 'Content-Type: application/x-www-form-urlencoded';

			curl_setopt($this->curl_handle, CURLOPT_POST, true);
			curl_setopt($this->curl_handle, CURLOPT_POSTFIELDS, OAuthUtil::joinParametersMap($req->getPostParameters()));
		}
		else
		{
			curl_setopt($this->curl_handle, CURLOPT_POSTFIELDS, array());
			curl_setopt($this->curl_handle, CURLOPT_HTTPGET, true);
		}

		curl_setopt($this->curl_handle, CURLOPT_HTTPHEADER, $http_headers);

		// Fetch the response synchronously:
		$response = curl_exec($this->curl_handle);
		$info = curl_getinfo($this->curl_handle);

		if(empty($response) || OAuthUtil::getIfSet($info, 'http_code') == 0)
		{
			// :TODO: not happy we throw this one here, should be moved to the base client class.
			throw new OAuthException('Contacting the remote server failed due to a network error: ' . curl_error($curl_handle), 0);
		}

		// If we received some response, create an OAuthClientResponse instance from it.
		return OAuthClientResponse::fromResponseStr($response);
	}

	// :TODO: move this to the base client class.
	public function _getTempToken($request_token_url, array $params = array())
	{
		// :TODO: We only support GET for request_token...
		$req = $this->createGetRequest($request_token_url, $params);

		$response = $this->executeRequest($req);

		$token_key = $response->getBodyParamValue('oauth_token');
		$token_secret = $response->getBodyParamValue('oauth_token_secret');

		if(empty($token_key) || empty($token_secret))
		{
			throw new Exception('We tried hard, but did not get a request/temp token from the server.');
		}

		return new OAuthToken($token_key, $token_secret);
	}

	// :TODO: move this to the base client class.
	public function _getAccessToken(array $params = array(), OAuthToken $token = NULL)
	{
		if(is_null($token))
		{
			// the $token argument is useful for clients that are not HTTP driven.
			$token = $this->token;
		}

		// :TODO: We only support POST for access_token...
		$req = $this->createPostRequest($this->access_token_url, $params);

		$response = $this->executeRequest($req);

		$token_key = $response->getBodyParamValue('oauth_token');
		$token_secret = $response->getBodyParamValue('oauth_token_secret');

		if(empty($token_key) || empty($token_secret))
		{
			throw new Exception('We tried hard, but did not get an access token from the server.');
		}

		return new OAuthToken($token_key, $token_secret);
	}

	/**
	 * Simple destructor, some cleanup, etc. Boring.
	 **/
	public function __destruct()
	{
		if($this->curl_handle)
		{
			curl_close($this->curl_handle);
		}
	}
}


class OAuthClientResponse
{
	protected $headers = array();
	protected $body;
	protected $status_code;
	protected $body_params = array();

	/**
	 * Constructs a response instance from an HTTP response's headers and body.
	 * Will throw on 400 and 401 return codes, if an oauth_problem has been specified.
	 **/
	public function __construct(array $headers, &$body, $status_code = 0)
	{
		// copy the body...
		$this->body = $body;

		// Update this->status_code, if necessary.
		// some derived classes may have set it already.
		if($status_code > 0)
		{
			$this->status_code = $status_code;
		}

		// need to lower case all header names :(
		foreach($headers as $key => $value)
		{
			$this->headers[strtolower($key)] = $value;
		}
		$headers = $this->headers;

		// will hold parameters from an www-form-urlencoded body:
		$body_params = array();

		// If the response content type is www-form-urlencoded, parse the body:
		if(preg_match('~^application/x-www-form-urlencoded~i', OAuthUtil::getIfSet($headers, 'content-type', '')))
		{
			$body_params = OAuthUtil::splitParametersMap($body);
		}

		if($this->status_code == 400 || $this->status_code == 401)
		{
			// The error codes 400 and 401 are suggested to have special meanings
			// in section 3.2. of the specs.
			$description = 'An error occured'; $problem = ''; $problem_extra_info = array();
			$problem_params = array();

			// If the server included a WWW-Authenticate response header,
			// it may include oauth_problem parameters. Therfore, parse it:
			if(isset($headers['www-authenticate']))
			{
				$problem_params = OAuthUtil::parseHttpAuthorizationHeader($headers['www-authenticate'], true);
				// :TODO: Maybe save the realm some place?
				unset($problem_params['realm']);
			}

			// If the WWW-Authenticate response header doesn't have an oauth_problem,
			// look for it in the body.
			if(empty($problem_params['oauth_problem']))
			{
				$problem_params = $body_params;
			}

			// Handle the oauth_problem parameter along the guidelines
			// that http://oauth.pbworks.com/ProblemReporting suggests.
			if(!empty($problem_params['oauth_problem']))
			{
				// We found an oauth_problem parameter. Let's identify it.
				$problem = $problem_params['oauth_problem'];
				unset($problem_params['oauth_problem']);

				// Form a human-readable problem description:
				$advice .= ': ' . $problem;

				if(!empty($problem_params['oauth_problem_advice']))
				{
					$advice .= ': ' . $problem_params['oauth_problem_advice'];
				}
				unset($problem_params['oauth_problem_advice']);

				// The rest of the parameters probably contains more useful
				// information about the error.
				$problem_extra_info = $problem_params;
				unset($problem_params);

				// Bubble up this error.
				throw new OAuthException($description, $this->status_code, $problem, $problem_extra_info);
			}
		}

		$this->body_params = $body_params;
	}

	/**
	 * Constructs a response instance from a complete HTTP response string, including the headers.
	 **/
	public static function fromResponseStr(&$complete_response_str)
	{
		$headers = array();
		$body = '';
		$status_code = 0;

		OAuthUtil::splitHttpResponse($complete_response_str, $headers, $body, $status_code);
		unset($complete_response_str);

		return new self($headers, $body, $status_code);
	}

	/**
	 * Returns the HTTP status code. Most probably between 100 and 500-something.
	 **/
	public function getStatusCode()
	{
		return $this->status_code;
	}

	/**
	 * Returns the value of the HTTP header with the name $header_name.
	 **/
	public function getHeaderValue($header_name)
	{
		return OAuthUtil::getIfSet($this->headers, strtolower($header_name), '');
	}

	/**
	 * If the body has been www-form-urlencoded, this method will return
	 * the value of the parameter that has the name $body_param_name.
	 **/
	public function getBodyParamValue($body_param_name)
	{
		return OAuthUtil::getIfSet($this->body_params, $body_param_name, '');
	}

	/**
	 * Returns the entire response body as a string.
	 **/
	public function getBody()
	{
		return $this->body;
	}
}

