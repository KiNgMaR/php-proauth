<?php

require_once './OAuthUtils.php';
require_once './OAuthRequest.php';
require_once './OAuthSignature.php';


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

	public function createRequest($url, array $get_params = array(), array $post_params = array())
	{
		$req = new OAuthClientRequest($this->consumer, $this->token, (count($_POST) > 0 ? 'POST' : 'GET'), $url);

		$req->setGetParameters($get_params);
		$req->setPostParameters($post_params);

		return $req;
	}

	public function createPostRequest($url, array $params = array())
	{
		$req = new OAuthClientRequest($this->consumer, $this->token, 'POST', $url);

		$req->setPostParameters($params);

		return $req;
	}

	public function createGetRequest($url, array $params = array())
	{
		$req = new OAuthClientRequest($this->consumer, $this->token, 'GET', $url);

		$req->setPostParameters($params);

		return $req;
	}
}


class OAuthClientRequest extends OAuthRequest
{
	public function __construct(OAuthConsumer $consumer, OAuthToken $token, $http_method, $url)
	{
		parent::__construct();

		if(strcasecmp($http_method, 'POST') || strcasecmp($http_method, 'GET'))
		{
			throw new OAuthException('Unsupported HTTP method in OAuthClientRequest.');
		}

		$this->params_oauth['oauth_consumer_key'] = $consumer->getKey();
		$this->params_oauth['oauth_token'] = $token->getToken();
		$this->params_oauth['oauth_signature_method'] = $token->getToken();
	}

	public function setGetParameters(array $new_params)
	{
		$this->params_get = $new_params;
	}

	public function setPostParameters(array $new_params)
	{
		$this->params_post = $new_params;
	}
}
