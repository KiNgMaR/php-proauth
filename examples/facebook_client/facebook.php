<?php

$_config = array(
	/* get your own app key + secret at http://www.facebook.com/developers */
	'key' => '', /* App ID, not API key! */
	'secret' => ''
);

/* include OAuth 2.0 client library */
require_once dirname(__FILE__) . '/../../lib/oauth/OAuth2Client.php';


if(isset($_GET['login']))
{
	$clnt = new OAuth2CurlClient();
	$clnt->setEndpoints('https://graph.facebook.com/oauth/authorize', 'https://graph.facebook.com/oauth/access_token');
	$clnt->setClientId($_config['key'], $_config['secret']);

	$obt = new OAuth2AccessTokenObtainer('user_agent', $clnt);
	$obt->setRedirectUrl('http://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME']);

	$obt->webFlowRedirect();
}

