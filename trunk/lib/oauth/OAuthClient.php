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

	public function __construct(OAuthConsumer $consumer, OAuthToken $token, OAuthSignatureMethod $signature_method)
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
	public function __construct(OAuthClient $client, $http_method, $url)
	{
		parent::__construct();

		if(strcasecmp($http_method, 'POST') || strcasecmp($http_method, 'GET'))
		{
			throw new OAuthException('Unsupported HTTP method in OAuthClientRequest.');
		}

		$this->client = $client;
		$this->http_method = $http_method;

		// :TODO: handle URLs with GET query parameters.
		// maybe parse them, or throw an error.
		$this->request_url = $url;

		$this->params_oauth['oauth_consumer_key'] = $consumer->getKey();
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
		$this->params_oauth['oauth_timestamp'] = $this->client->generateTimestamp();
		$this->params_oauth['oauth_nonce'] = $this->client->generateNonce();

		$this->params_oauth['oauth_signature_method'] = $this->client->getSignatureMethod->getName();
		$this->params_oauth['oauth_signature'] = $this->client->getSignatureMethod->buildSignature($this,
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
			$result .= OAuthUtil::urlEncode($key) . '="' . OAuthUtil::urlEncode($value) . '",';
		}

		return substr($result, 0, -2);
	}
}


class OAuthClientWithCurl extends OAuthClientBase
{
	protected $curl_handle = NULL;
	protected $request_token_url = '';
	protected $authorize_url = '';
	protected $access_token_url = '';

	/**
	 * @see OAuthClientBase::__construct
	 **/
	public function __construct(OAuthConsumer $consumer, OAuthToken $token, OAuthSignatureMethod $signature_method)
	{
		parent::__construct($consumer, $token, $signature_method);

		$this->curl_handle = curl_init();
		// set all the necessary curl options...
		curl_setopt($this->curl_handle, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($this->curl_handle, CURLOPT_HEADER, true);

		curl_setopt($this->curl_handle, CURLOPT_CONNECTTIMEOUT, 5);
		curl_setopt($this->curl_handle, CURLOPT_TIMEOUT, 30);

		curl_setopt($this->curl_handle, CURLOPT_USERAGENT, 'php-proauth (http://code.google.com/p/php-proauth/) using libcurl');

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
	 * Sets the Service Provider-provided URLs this client instance will use
	 * to get a temp/request token, to ask for authorization and to get the session/access token.
	 * Once you obtained an access token, you do no longer need this method.
	 **/
	public function setOAuthFlowUrls($request_token_url, $authorize_url, $access_token_url)
	{
		$this->request_token_url = $request_token_url;
		$this->authorize_url = $authorize_url;
		$this->access_token_url = $access_token_url;
	}

	/**
	 * Executes the given request using libcurl.
	 * Returns the response body as a string or
	 * throws an OAuchException on errors.
	 **/
	public function executeRequest(OAuthRequest $req)
	{
		$req->sign();

		$http_headers = array();

		$http_headers[] = 'Authorization: ' . $req->getAuthorizationHeader();

		$url = $req->getRequestUrl(true);
		$url .= '?' . OAuthUtil::joinParametersMap($req->getGetParameters());

		curl_setopt($this->curl_handle, CURLOPT_URL, $url);

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

		$response = curl_exec($this->curl_handle);
	}

	public function getTempToken(array $params = array())
	{
		
	}

	public function getAuthorizeUrl(array $params = array(), OAuthToken $token = NULL)
	{
	}

	public function __destruct()
	{
		if($this->curl_handle)
		{
			curl_close($this->curl_handle);
		}
	}
}

