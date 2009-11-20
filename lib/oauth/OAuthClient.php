<?php

if(!defined('_OAUTH_LIB_DIR'))
{
	define('_OAUTH_LIB_DIR', dirname(__FILE__) . '/');
}

require_once _OAUTH_LIB_DIR . 'OAuthUtil.php';
require_once _OAUTH_LIB_DIR . 'OAuthRequest.php';
require_once _OAUTH_LIB_DIR . 'OAuthSignature.php';


class OAuthClient
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
}

