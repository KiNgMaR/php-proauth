<?php

class OAuthShared
{
	public static function setUpCurl(&$ch)
	{
		$ch = curl_init();
		// set all the necessary curl options...
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_HEADER, true);
		curl_setopt($ch, CURLOPT_FAILONERROR, false);

		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
		curl_setopt($ch, CURLOPT_TIMEOUT, 30);

		curl_setopt($ch, CURLOPT_USERAGENT, 'php-proauth/1.0 (http://code.google.com/p/php-proauth/) using libcurl');

		// ignore this stupid and soon-to-be-deprecated warning:
		// CURLOPT_FOLLOWLOCATION cannot be activated when in safe_mode or an open_basedir is set.
		@curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($ch, CURLOPT_MAXREDIRS, 10);

		// to avoid possibly unwanted SSL problems. :TODO: make this configurable.
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

		// enable compression where supported:
		curl_setopt($ch, CURLOPT_ENCODING, '');
	}
}

