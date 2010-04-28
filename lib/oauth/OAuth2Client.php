<?php
/*
 * php-proauth (c) Ingmar "KiNgMaR" Runge 2009-2010
 * You are free to use this code under the terms of The MIT License.
 * You should have received a copy of The MIT License in LICENSE.txt with this file.
 */

if(!defined('_OAUTH2_LIB_DIR'))
{
	define('_OAUTH2_LIB_DIR', dirname(__FILE__) . '/');
}

require_once _OAUTH2_LIB_DIR . 'OAuth2Util.php';
require_once _OAUTH2_LIB_DIR . 'OAuthXShared.php';


/* some constants for OAuth2AccessTokenObtainer's constructor */

define('OAUTH2_FLOW_USER_AGENT', 1);
define('OAUTH2_FLOW_WEB_SERVER', 2);
define('OAUTH2_FLOW_DEVICE', 3);
define('OAUTH2_FLOW_USER_PASS', 4);
define('OAUTH2_FLOW_CLIENT_CREDENTIALS', 5);
define('OAUTH2_FLOW_ASSERTION', 6);

// please note that the values of the above constants have to match
// the order in the array in OAuth2AccessTokenObtainer::__construct.


abstract class OAuth2ClientBase
{
	/**
	 * Endpoint URLs
	 **/
	protected $url_authorization, $url_token;
	/**
	 * Client ID and optional secret
	 **/
	protected $client_id, $client_secret;
	/** 
	 * If an access token has been obtained (previously or just now),
	 * it will be stored here.
	 * @type OAuth2AccessToken
	 **/
	protected $access_token = NULL;
	/**
	 * An instance of a class derived from OAuth2SignatureMethod
	 **/
	protected $access_secret_type = NULL;


	public function __construct(OAuth2AccessToken $access_token = NULL)
	{
		$this->access_token = $access_token;
	}

	/**
	 * Sets the endpoint URLs that are used for obtaining and refreshing access tokens.
	 **/
	public function setEndpoints($url_authorization, $url_token)
	{
		if(filter_var($url_authorization, FILTER_VALIDATE_URL) && preg_match('~^https://.+$~ui', $url_authorization))
		{
			$this->url_authorization = $url_authorization;
		}
		else
		{
			throw new OAuth2Exception('Invalid authorization endpoint URL. Needs to be a valid https:// URL.');
		}

		if(filter_var($url_token, FILTER_VALIDATE_URL) && preg_match('~^https://.+$~ui', $url_token))
		{
			$this->url_token = $url_token;
		}
		else
		{
			throw new OAuth2Exception('Invalid token endpoint URL. Needs to be a valid https:// URL.');
		}
	}

	/**
	 * Sets the client ID and an optional secret string that is used for
	 * obtaining and refreshing access tokens.
	 **/
	public function setClientId($id, $secret = NULL)
	{
		$this->client_id = (string)$id;
		$this->secret = (string)$secret;
	}

	public function getAuthEndpointUrl() { return $this->url_authorization; }
	public function getTokenEndpointUrl() { return $this->url_token; }

	public function getClientId() { return $this->client_id; }
	public function getClientSecret() { return $this->client_secret; }

	/**
	 * All auth flows besides 'device' can optionally issue a token+secret instead
	 * of a bearer token. To enable this behavior, make sure to set up a signature
	 * method that your target server supports.
	 **/
	public function setAccessSecretType(OAuth2SignatureMethod $inst)
	{
		$this->access_secret_type = $inst;
	}

	public function getAccessSecretType()
	{
		return $this->access_secret_type;
	}
}


class OAuth2CurlClient extends OAuth2ClientBase
{
	protected $curl_handle;

	public function __construct(OAuth2AccessToken $access_token = NULL)
	{
		parent::__construct($access_token);

		OAuthShared::setUpCurl($this->curl_handle);
	}


}


class OAuth2AccessTokenObtainer
{
	protected $flow_type;
	protected $client;

	/**
	 * Used for: user_agent and web_server
	 **/
	protected $redirect_uri;

	/**
	 * Used for: user_agent and web_server
	 **/
	protected $state_string = '';

	/**
	 * Used for: user_agent and web_server
	 **/
	protected $immediate = false;


	public function __construct($flow_type, OAuth2ClientBase $client_instance)
	{
		$valid_flow_types = array('user_agent', 'web_server', 'device',
			'username', 'client_cred', 'assertion');

		if(is_string($flow_type) && in_array($flow_type, $valid_flow_types))
		{
			$this->flow_type = $flow_type;
		}
		else
		{
			$type_index = (int)$flow_type;

			if($type_index > 0 && $type_index <= count($valid_flow_types))
			{
				$this->flow_type = $valid_flow_types[$type_index];
			}
			else
			{
				throw new OAuth2Exception('Unknown Access Token Auth Flow Type.');
			}
		}

		/*** :TODO: ***/
		if($this->flow_type != 'user_agent' && $this->flow_type != 'web_server')
		{
			throw new OAuth2Exception('Sorry, this version of the library only supports the ' .
				'user_agent and web_server authentication flow types.');
		}
		/*** :TODO: ***/

		$this->client = $client_instance;
	}

	public function setRedirectUrl($url)
	{
		if(filter_var($url, FILTER_VALIDATE_URL))
		{
			$this->redirect_url = $url;
		}
		else
		{
			throw new OAuth2Exception('Invalid redirect URL.');
		}
	}

	public function setStateData($data)
	{
		$this->state_string = (string)$data;
	}

	public function getStateData() { return $this->state_string; }

	public function setImmediate($bool)
	{
		$this->immediate = (bool)$bool;
	}

	/**
	 * Use this for the user_agent and web_server authentication flows.
	 * It returns the URL of the authorization endpoint where you should redirect
	 * your visitor's browser to. You can use @webFlowRedirect to do that.
	 * Working in full accordance with sections 3.5.1.1. and 3.5.2.1. of the oauth2 draft.
	 **/
	public function webFlowGetRedirectUrl(array $additional_params = array())
	{
		$url = $this->client->getAuthEndpointUrl();

		if(empty($url))
		{
			throw new OAuth2Exception('The client class instance has not been assigned an authorization endpoint URL.');
		}

		$params = array('type' => $this->flow_type,
			'client_id' => $this->client->getClientId());

		if(empty($params['client_id']))
		{
			throw new OAuth2Exception('The client class instance is missing a client ID.');
		}

		if(!empty($this->redirect_url))
		{
			$params['redirect_uri'] = $this->redirect_url;
		}

		if(!empty($this->state_string))
		{
			if(strpos($this->redirect_url, '?') !== false)
			{
				throw new OAuth2Exception('You can not set a state parameter and use a query ' .
					'string in the redirect URL at the same time.');
			}

			$params['state'] = $this->state_string;
		}

		$params['immediate'] = ($this->immediate ? 'true' : 'false');

		if($this->flow_type == 'user_agent' && !is_null($this->client->getAccessSecretType()))
		{
			// the user_agent flow can optionally receive a secret with the access token.
			$params['secret_type'] = $this->client->getAccessSecretType()->getName();
		}

		$params = array_merge($additional_params, $params);

		return $url . '?' . http_build_query($params, '', '&');
	}

	/**
	 * @see webFlowGetRedirectUrl
	 **/
	public function webFlowRedirect(array $additional_params = array())
	{
		header('HTTP/1.0 302 Found');
		header('Location: ' . $this->webFlowGetRedirectUrl($additional_params));
	}

	/**
	 * Used for the web_server flow. Call this to extract the information from the
	 * query string the authorization server put together.
	 * If the user authorized the app, you can use @getStateData etc.
	 **/
	public function webServerDidUserAuthorize()
	{
		
	}

	
}



