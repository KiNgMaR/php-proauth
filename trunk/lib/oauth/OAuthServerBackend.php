<?php

abstract class OAuthServerBackend
{
	public const RESULT_ERROR = -1;
	public const RESULT_OK = 1;
	public const RESULT_DUPE = 2;

	public const RESULT_RATE_LIMITED = 3;
	public const RESULT_NOT_FOUND = 4;
	public const RESULT_DISABLED = 5;

	public const RESULT_DUPE_NONCE = 6;
	public const RESULT_BAD_TIMESTAMP = 7;
	public const RESULT_BAD_TOKEN = 8;

	abstract public function getConsumerByKey($consumer_key);
	abstract public function checkNonceAndTimeStamp($nonce, $timestamp, OAuthConsumer $consumer, OAuthToken $token);
	abstract public function addTempToken(OAuthConsumer $consumer, OAuthToken $new_token, $callback_url);
}

