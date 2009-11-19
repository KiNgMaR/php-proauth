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


class OAuthSignatureHMACSHA1 extends OAuthSignatureMethod
{
	public function getName()
	{
		return 'HMAC-SHA1';
	}

	/**
	 * @author Marc Worrell <marcw@pobox.com>
	 * @source http://code.google.com/p/oauth-php/source/browse/trunk/library/signature_method/OAuthSignatureMethod_HMAC_SHA1.php
	 **/
	protected function buildSignature(OAuthRequest $req, OAuthConsumer $consumer, OAuthToken $token)
	{
		$base_string = $req->getSignatureBaseString();

		$key_parts = array(
			$consumer->getSecret(),
			is_object($token) ? $token->getSecret() : ''
		);

		$key_parts = OAuthUtil::urlEncode($key_parts);
		$key = implode('&', $key_parts);

		if(function_exists('hash_hmac'))
		{
			$hmac = hash_hmac('sha1', $base_string, $key, true);
		}
		else
		{
			$blocksize = 64;

			if(strlen($key) > $blocksize)
			{
				$key = pack('H*', sha1($key));
			}

			$key = str_pad($key, $blocksize, chr(0x00));
			$ipad = str_repeat(chr(0x36), $blocksize);
			$opad = str_repeat(chr(0x5c), $blocksize);

			$hmac = pack('H*', sha1(($key ^ $opad) . pack('H*', sha1(($key ^ $ipad) . $base_string))));
		}

		return base64_encode($hmac);
	}
}

