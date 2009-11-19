<?php

require_once './OAuthUtil.php';
require_once './OAuthRequest.php';
require_once './OAuthSignature.php';
require_once './OAuthServerBackend.php';


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

		$consumer = $this->getConsumer();

		$this->checkSignature($req, $consumer, NULL);

		$callback_url = $req->getCallbackParameter();

		if(!empty($callback_url) && !filter_var($callback_url, FILTER_VALIDATE_URL) && $callback_url != 'oob')
		{
			throw new OAuthException('Invalid callback used.', 400);
		}

		$temp_secret = OAuthUtil::randomString(40);

		do
		{
			$new_token = new OAuthToken(OAuthUtil::randomString(20), $temp_secret);
			$result = $this->backend->addTempToken($consumer, $new_token, $callback_url);
		} while($result == OAuthServerBackend::RESULT_DUPE);

		if($result != OAuthServerBackend::RESULT_OK)
		{
			throw new OAuthException('Creating a temporary token failed.');
		}

		$new_token->setAdditionalParam('oauth_callback_confirmed', (empty($callback_url) ? 'false' : 'true'));

		return $new_token;
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
		$this->http_method = OAuthUtil::getIfSet($_SERVER, 'REQUEST_METHOD');

		if(empty($this->http_method))
		{
			// :TODO: find out if this actually happens and how bad the fallback is.
			$this->http_method = (count($_POST) > 0 ? 'POST' : 'GET');
		}


		// Determine request URL:
		$host = OAuthUtil::getIfSet($_SERVER, 'HTTP_HOST');

		if(empty($host))
		{
			throw new OAuthException('The requesting client did not send the HTTP Host header which is required by this implementation.', 400);
		}

		$scheme = (OAuthUtil::getIfSet($_SERVER, 'HTTPS', 'off') === 'on' ? 'https' : 'http');

		$port = (int)$_SERVER['SERVER_PORT'];

		$this->request_url = $scheme . '://' . $host .
			($port == ($scheme == 'https' ?  443 : 80) ? '' : ':' . $port) .
			$_SERVER['REQUEST_URI'];


		// extract oauth parameters from the Authorization
		// HTTP header. If present, these take precedence over
		// GET and POST parameters.
		$header_parameters = OAuthUtil::getPageRequestAuthorizationHeader();

		if(!empty($header_parameters))
		{
			$header_parameters = OAuthUtil::parseHttpAuthorizationHeader($header_parameters);
			$realm = '';

			if(is_array($header_parameters) && count($header_parameters) > 0)
			{
				$realm = OAuthUtil::getIfSet($header_parameters, 'realm');
				unset($header_parameters['realm']);

				$this->params_oauth = $header_parameters;
			}

			$this->setRealm($realm);
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
			if(OAuthUtil::isKnownOAuthParameter($key))
			{
				if(!isset($this->params_oauth[$key]))
				{
					$this->params_oauth[$key] = $value;
					unset($_POST[$key]);
				}
				else
				{
					throw new OAuthException('You cannot specify the "' . $key . '" parameter multiple times.', 400);
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
			if(OAuthUtil::isKnownOAuthParameter($key))
			{
				if(!isset($this->params_oauth[$key]))
				{
					$this->params_oauth[$key] = $value;
					unset($_GET[$key]);
				}
				else
				{
					throw new OAuthException('You cannot specify the "' . $key . '" parameter multiple times.', 400);
				}
			}
			else
			{
				if(isset($this->params_post[$key]))
				{
					throw new OAuthException('We do not support GET and POST parameters with the same name.', 400);
				}

				$this->params_get[$key] = $value;
			}
		}

		// whew, done.
	}

	/**
	 * Returns the oauth_callback parameter's value or an empty string.
	 **/
	public function getCallbackParameter()
	{
		return OAuthUtil::getIfSet($this->params_oauth, 'oauth_callback', '');
	}
}

