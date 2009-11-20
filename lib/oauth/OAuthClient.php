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
		$req = new OAuthClientRequest($this->consumer, $this->token, 'GET', $url);

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
}


class OAuthClientRequest extends OAuthRequest
{
	protected $consumer;
	protected $token;

	/**
	 * Usually invoked by OAuthClient. It's not recommended to create instances by other means.
	 **/
	public function __construct(OAuthConsumer $consumer, OAuthToken $token, $http_method, $url)
	{
		parent::__construct();

		if(strcasecmp($http_method, 'POST') || strcasecmp($http_method, 'GET'))
		{
			throw new OAuthException('Unsupported HTTP method in OAuthClientRequest.');
		}

		// save to calculate the signature later:
		$this->consumer = $consumer;
		$this->token = $token;

		$this->params_oauth['oauth_consumer_key'] = $consumer->getKey();
		$this->params_oauth['oauth_token'] = $token->getToken();
		// we do not add oauth_version=1.0 since it's optional (section 7 of the OAuth Core specs)
	}

	/**
	 * Replaces the existing GET query parameters.
	 **/
	public function setGetParameters(array $new_params)
	{
		$this->params_get = $new_params;
	}

	/**
	 * Replaces the existing POST parameters.
	 **/
	public function setPostParameters(array $new_params)
	{
		$this->params_post = $new_params;
	}
}

