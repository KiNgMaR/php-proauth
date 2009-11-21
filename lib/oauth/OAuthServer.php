<?php

if(!defined('_OAUTH_LIB_DIR'))
{
	define('_OAUTH_LIB_DIR', dirname(__FILE__) . '/');
}

require_once _OAUTH_LIB_DIR . 'OAuthUtil.php';
require_once _OAUTH_LIB_DIR . 'OAuthRequest.php';
require_once _OAUTH_LIB_DIR . 'OAuthSignature.php';
require_once _OAUTH_LIB_DIR . 'OAuthServerBackend.php';


class OAuthServer
{
	protected $backend;
	protected $user_data = NULL;
	protected $signature_methods = array();
	protected $superglobals_auto_export;

	/**
	 * @param OAuthServerBackend backend The backend. Yeah.
	 * @param bool superglobals_auto_export If true, OAuthServerRequest parameters validated against \
	 *   this class will be exported as $_GET, $_POST and $_REQUEST automatically.
	 **/
	public function __construct(OAuthServerBackend $backend, $superglobals_auto_export = false)
	{
		$this->backend = $backend;
		$this->superglobals_auto_export = $superglobals_auto_export;
	}

	public function addSignatureMethod(OAuthSignatureMethod $method)
	{
		$signature_methods[strtoupper($method->getName())] = $method;
	}

	/**
	 * For internal use, checks if the OAuth version of $req is okay.
	 **/
	protected function checkOAuthVersion(OAuthServerRequest $req)
	{
		$version = $req->getOAuthVersion();

		if(!version_compare($version, '1.0', '=='))
		{
			throw new OAuthException('OAuth version "' . $version . '" is not supported!',
				400, 'version_rejected', array('oauth_acceptable_versions' => '1.0-1.0'));
		}

		return $version;
	}

	/**
	 * For internal use, returns an OAuthConsumer instance.
	 **/
	protected function getConsumer(OAuthServerRequest $req)
	{
		$consumer_key = $req->getConsumerKey();

		if(!$consumer_key)
		{
			throw new OAuthException('Invalid consumer key.', 401, 'consumer_key_unknown');
		}

		$consumer = $this->backend->getConsumerByKey($consumer_key);

		if($consumer === OAuthServerBackend::RESULT_RATE_LIMITED)
		{
			throw new OAuthException('Too many requests have been made. Throttling.', 401, 'consumer_key_refused');
		}
		elseif($consumer === OAuthServerBackend::RESULT_DISABLED)
		{
			throw new OAuthException('This consumer key has been disabled permanently.', 401, 'consumer_key_rejected');
		}
		elseif($consumer === OAuthServerBackend::RESULT_NOT_FOUND)
		{
			throw new OAuthException('Consumer not found.', 500);
		}
		else
		{
			throw new OAuthException('Backend returned an incorrect value from getConsumerByKey');
		}

		return $consumer;
	}

	/**
	 * For internal use, returns the appropriate OAuthSignatureMethod instance.
	 **/
	protected function getSignatureMethod(OAuthServerRequest $req)
	{
		$method = strtoupper($req->getSignatureMethod());

		if(!isset($this->signature_methods[$method]))
		{
			throw new OAuthException('Signature method "' . $signature_method . '" not supported.', 400, 'signature_method_rejected');
		}

		return $this->signature_methods[$signature_method];
	}

	/**
	 * For internal use, checks nonce, timestamp and token!
	 **/
	protected function checkSignature(OAuthServerRequest $req, OAuthConsumer $consumer, OAuthToken $token)
	{
		$req->getNonceAndTimeStamp($nonce, $timestamp);

		$result = $this->backend->checkNonceAndTimeStamp($nonce, $timestamp, $consumer, $token);

		if($result == OAuthServerBackend::RESULT_OK)
		{
			$sig_method = $this->getSignatureMethod($req);

			if(!$sig_method->checkSignature($req, $consumer, $token))
			{
				throw new OAuthException('Invalid signature.', 401, 'signature_invalid');
			}

			if($this->superglobals_auto_export)
			{
				$req->exportAsSuperglobals();
			}
		}
		elseif($result == OAuthServerBackend::RESULT_DUPE_NONCE)
		{
			throw new OAuthException('A previously used nonce has been used again.', 401, 'nonce_used');
		}
		elseif($result == OAuthServerBackend::RESULT_BAD_TIMESTAMP)
		{
			throw new OAuthException('The request timestamp is invalid.', 401, 'timestamp_refused');
		}
		elseif($result == OAuthServerBackend::RESULT_BAD_TOKEN)
		{
			throw new OAuthException('The token is invalid, or has expired.', 401, 'token_rejected');
		}
		else
		{
			throw new OAuthException('Backend returned an incorrect value from checkNonceAndTimeStamp');
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
		$callback_url = OAuthUtils::validateCallbackURL($callback_url);

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

		if(preg_match('~^(.+):(\d+)$~', $host, $match))
		{
			if((int)$match[1] != $port)
			{
				throw new OAuthException('Bad port in the HTTP Host header.', 400);
			}
			$host = $match[0];
		}

		// courtesy: http://stackoverflow.com/questions/106179/regular-expression-to-match-hostname-or-ip-address
		if(!preg_match('~^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$~', $host)
			&& !preg_match('~^((\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])$~', $host))
		{
			throw new OAuthException('Invalid HTTP Host header.', 400);
		}

		$this->request_url = $scheme . '://' . $host .
			($port == ($scheme == 'https' ? 443 : 80) ? '' : ':' . $port) .
			$_SERVER['REQUEST_URI'];


		$page_request_headers = OAuthUtil::getPageRequestHeaders();

		// extract oauth parameters from the Authorization
		// HTTP header. If present, these take precedence over
		// GET and POST parameters.
		$header_parameters = OAuthUtil::getIfSet($page_request_headers, 'authorization');

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

		// We rely on PHP to parse the $_POST and $_GET parameters for us.
		// This *could* break in some weird cases, but I am not aware of any
		// situation out in the wild where that would happen. PHP uses
		// urldecode() to decode the parameters, which works in accordance to
		// section 5.1 of the core specs and section 3.4.1.3.1. of the hammer-draft.
		// C.f. OAuthUtil::urlDecode()

		$this->params_post = array();
		$this->params_get = array();

		$content_type = trim(OAuthUtil::getIfSet($page_request_headers, 'content-type'));

		if(preg_match('~^application/x-www-form-urlencoded~$i', $content_type))
		{
			// extract POST parameters...
			foreach($_POST as $key => $value)
			{
				if(OAuthUtil::isKnownOAuthParameter($key))
				{
					if(!isset($this->params_oauth[$key]))
					{
						$this->params_oauth[$key] = $value;
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
		}

		// extract GET parameters...
		foreach($_GET as $key => $value)
		{
			if(OAuthUtil::isKnownOAuthParameter($key))
			{
				if(!isset($this->params_oauth[$key]))
				{
					$this->params_oauth[$key] = $value;
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

		// whew, done with the parameter extraction.

		if(count($this->params_oauth) == 0)
		{
			// the Service Provider can now send
			// header('WWW-Authenticate: OAuth realm="http://sp.example.com/"');
			// if he deems it necessary.
			throw new NonOAuthRequestException();
		}
	}

	/**
	 * Overwrites the $_GET, $_POST and $_REQUEST superglobals with the data from this
	 * request. They won't contain any known oauth_ parameters and $_REQUEST will
	 * be cookie-parameter free.
	 **/
	public function exportAsSuperglobals()
	{
		// POST parameters would take precedence here, but we do not
		// support POST and GET parameters of the same name, so
		// yeah. Just writing this down here so we know later.
		$_REQUEST = array_merge($this->params_get, $this->params_post);

		$_GET = $this->params_get;
		$_POST = $this->params_post;

		// we cannot validate file uploads right now,
		// if there were any files, $_POST will be empty too
		// (because Content-Type isn't application/x-www-form-urlencoded)
		$_FILES = array();
	}

	/**
	 * Returns the oauth_callback parameter's value or an empty string.
	 **/
	public function getCallbackParameter()
	{
		return OAuthUtil::getIfSet($this->params_oauth, 'oauth_callback', '');
	}
}


class NonOAuthRequestException extends Exception {}
