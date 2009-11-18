<?php

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
