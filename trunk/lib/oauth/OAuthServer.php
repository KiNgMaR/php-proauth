<?php

class OAuthServer
{
	protected $backend;
	protected $user_data = NULL;
	protected $signature_methods = array();

	public function __construct(OAuthServerBackend $backend)
	{
		$this->backend = $backend;
	}

	public function addSignatureMethod(OAuthSignatureMethod $method)
	{
		$signature_methods[strtoupper($method->getName())] = $method;
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
			throw new OAuthException('Invalid consumer key.', 401);
		}

		$consumer = $this->backend->getConsumerByKey($consumer_key);

		if(!$consumer)
		{
			throw new OAuthException('Consumer not found.', 401);
		}

		return $consumer;
	}

	/**
	 * For internal use, returns the appropriate OAuthSignatureMethod instance.
	 **/
	protected function getSignatureMethod(OAuthRequest $req)
	{
		$method = strtoupper($req->getSignatureMethod());

		if(!isset($this->signature_methods[$method]))
		{
			throw new OAuthException('Signature method "' . $signature_method . '" not supported.', 400);
		}

		return $this->signature_methods[$signature_method];
	}

	/**
	 * For internal use, checks nonce, timestamp and token!
	 **/
	protected function checkSignature(OAuthRequest $req, OAuthConsumer $consumer, OAuthToken $token)
	{
		$req->getNonceAndTimeStamp($nonce, $timestamp);

		if($this->backend->checkNonceAndTimeStamp($nonce, $timestamp, $consumer, $token))
		{
			$sig_method = $this->getSignatureMethod($req);

			if(!$sig_method->checkSignature($req, $consumer, $token))
			{
				throw new OAuthException('Invalid signature.', 401);
			}
		}
		else
		{
			throw new OAuthException('Invalid nonce, timestamp or token.', 401);
		}
	}

	/**
	 * Auth Flow Server API: Implements section 6.1. "Obtaining an Unauthorized Request Token"
	 * of the OAuth Core specs.
	 **/
	public function requestToken()
	{
		$req = new OAuthServerRequest();
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


class OAuthServerRequest extends OAuthRequest
{
	public function __construct()
	{
		parent::__construct();

		// Determine HTTP method...
		$this->http_method = OAuthUtils::getIfSet($_SERVER, 'REQUEST_METHOD');

		if(empty($this->http_method))
		{
			// :TODO: find out if this actually happens and how bad the fallback is.
			$this->http_method = (count($_POST) > 0 ? 'POST' : 'GET');
		}


		// Determine request URL:
		$host = OAuthUtils::getIfSet($_SERVER, 'HTTP_HOST');

		if(empty($host))
		{
			throw new OAuthException('The requesting client did not send the HTTP Host header which is required by this implementation.');
		}

		$scheme = (OAuthUtils::getIfSet($_SERVER, 'HTTPS', 'off') === 'on' ? 'https' : 'http');

		$port = (int)$_SERVER['SERVER_PORT'];

		$this->request_url = $scheme . '://' . $host .
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

				$this->params_oauth = $header_parameters;
			}

			/* :TODO: Check and/or store the realm parameter here... */
		}

		// The next paragraphs implement section 5.2 from the OAuth Core specs.
		// ... at least mostly... :TODO: we do not care about the Content-Type (application/x-www-form-urlencoded)
		// and we rely on PHP to parse the $_POST and $_GET parameters for us.
		// This *could* break in some weird cases, where URL decoding is done very strangely...
		// ... but that's okay for now!

		// extract POST parameters...
		$this->params_post = array();

		foreach($_POST as $key => $value)
		{
			if(OAuthUtils::isKnownOAuthParameter($key))
			{
				if(!isset($this->params_oauth[$key]))
				{
					$this->params_oauth[$key] = $value;
					unset($_POST[$key]);
				}
				else
				{
					throw new OAuthException('You cannot specify the "' . $key . '" parameter multiple times.');
				}
			}
			else
			{
				$this->params_post[$key] = $value;
			}
		}

		// extract GET parameters...
		$this->params_get = array();

		foreach($_GET as $key => $value)
		{
			if(OAuthUtils::isKnownOAuthParameter($key))
			{
				if(!isset($this->params_oauth[$key]))
				{
					$this->params_oauth[$key] = $value;
					unset($_GET[$key]);
				}
				else
				{
					throw new OAuthException('You cannot specify the "' . $key . '" parameter multiple times.');
				}
			}
			else
			{
				if(isset($this->params_post[$key]))
				{
					throw new OAuthException('We do not support GET and POST parameters with the same name.');
				}

				$this->params_get[$key] = $value;
			}
		}

		// whew, done.
	}
}


abstract class OAuthSignatureMethod
{
	/**
	 * Must return the name of the method, e.g. HMAC-SHA1 or PLAINTEXT.
	 * @return string
	 **/
	abstract public function getName();
	/**
	 * Must build the signature string from the given parameters and return it.
	 * @return string
	 **/
	abstract protected function buildSignature(OAuthRequest $req, OAuthConsumer $consumer, OAuthToken $token);

	/**
	 * Compares the given $signature_string with the one that is defined by req, consumer and token.
	 * If $signature_string is NULL, the oauth_signature parameter from $req will be used.
	 * @return bool
	 **/
	public function checkSignature(OAuthRequest $req, OAuthConsumer $consumer, OAuthToken $token, $signature_string = NULL)
	{
		$correct_string = $this->buildSignature($req, $consumer, $token);

		if(is_null($signature_string))
		{
			$signature_string = $req->getSignatureParameter();
		}

		// extra checks to make sure we never allow obviously faulty signature strings:
		return (is_string($signature_string) &&
			is_string($correct_string) &&
			!empty($signature_string) &&
			strcmp($correct_string, $signature_string) == 0);
	}
}

