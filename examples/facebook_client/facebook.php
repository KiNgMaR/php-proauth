<?php
/*
 * This example code is hereby released into Public Domain.
 */

$_config = array(
	/* get your own app key + secret at http://www.facebook.com/developers */
	'key' => '', /* App ID, not API key! */
	'secret' => ''
);

/* include OAuth 2.0 client library */
require_once dirname(__FILE__) . '/../../lib/oauth/OAuth2Client.php';


/* utility methods for obtaining an access token */
function getAnonClient()
{
	global $_config;

	$clnt = new OAuth2CurlClient();
	$clnt->setEndpoints('https://graph.facebook.com/oauth/authorize', 'https://graph.facebook.com/oauth/access_token');
	$clnt->setClientId($_config['key'], $_config['secret']);
	/* $clnt->setAccessSecretType(new OAuth2SignatureHmacSha256()); Facebook does not support token secrets */

	return $clnt;
}

function getObtainer($clnt = NULL)
{
	if(is_null($clnt))
	{
		$clnt = getAnonClient();
	}

	$obt = new OAuth2AccessTokenObtainer('web_server', $clnt);
	$obt->setRedirectUrl('http://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME'] . '?step2=1');

	return $obt;
}


if(isset($_GET['login']))
{
	/* step 1, user clicked "login with facebook link, redirect them to FB */
	$obt = getObtainer();
	$obt->webFlowRedirect();
}
elseif(isset($_GET['step2']))
{
	/* step 2, user authed our app at FB, so let's get the access token */
	$clnt = getAnonClient();
	$obt = getObtainer($clnt);

	if($obt->webServerDidUserAuthorize())
	{
		/* we should save the access token to the database or something
			so we can use it later to make calls and stuff */
		print_r($clnt->getAccessToken());
	}
	else
	{
		/* if they clicked "deny access", this will happen */
		echo 'WHY DON\'T YOU LIKE ME!!!!';
	}
}
else
{
	echo '<a href="?login=1">Log in with Facebook</a>';
}
