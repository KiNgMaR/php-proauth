<?php

namespace OAuth;

class Server
{
	protected $backend;
	protected $user_data = NULL;
	protected $signature_methods;

	public function __construct(Backend $backend)
	{
		$this->backend = $backend;
	}

	/**
	 * For internal use, checks if the OAuth version of $req is okay.
	 **/
	protected function checkOAuthVersion(OAuthRequest $req)
	{
		$version = $req->getOAuthVersion();

		if(!version_compare($version, '1.0', '=='))
		{
			throw new OAuthException('OAuth version "' . $version . '" is not supported!');
		}

		return $version;
	}

	/**
	 * For internal use, returns an OAuthConsumer instance.
	 **/
	protected function getConsumer(OAuthRequest $req)
	{
		$consumer_key = $req->getConsumerKey();

		if(!$consumer_key)
		{
			throw new OAuthException('Invalid consumer key.');
		}

		$consumer = $this->backend->getConsumerByKey($consumer_key);

		if(!$consumer)
		{
			throw new OAuthException('Consumer not found.');
		}

		return $consumer;
	}

	/**
	 * For internal use, checks nonce, timestamp and token!
	 **/
	protected function checkSignature(OAuthRequest $req, OAuthConsumer $consumer, OAuthToken $token)
	{
		$req->getNonceAndTimeStamp($nonce, $timestamp);

		if($this->backend->checkNonceAndTimeStamp($nonce, $timestamp, $consumer, $token))
		{
			
		}
		else
		{
			throw new OAuthException('Invalid nonce, timestamp or token.');
		}
	}

	/**
	 * Auth Flow Server API: Implements section 6.1. "Obtaining an Unauthorized Request Token"
	 * of the OAuth Core specs.
	 **/
	public function requestToken()
	{
		$req = OAuthRequest::createFromPageRequest();
		$this->checkOAuthVersion($req);
	}

	/**
	 * Auth Flow Server API: Implements the first part of section
	 * 6.2. "Obtaining User Authorization" of the OAuth Core specs.
	 **/
	public function authorize_checkToken()
	{

	}

	/**
	 * Auth Flow Server API: Implements the second part of section 6.2.
	 **/
	public function authorize_result($token, $authorized)
	{

	}

	/**
	 * Auth Flow Server API: Implements section 6.3. "Obtaining an Access Token".
	 **/
	public function accessToken()
	{

	}

	/**
	 * Use this method to verify an API call and its parameters.
	 * If the verification succeeds, you can use the parameters from $_GET and $_POST.
	 * @return mixed Returns the user data that the backend associated with the access_token session.
	 **/
	public function verifyApiCall()
	{
	
	}
}
