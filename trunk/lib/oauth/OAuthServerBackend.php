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
	abstract public function checkNonceAndTimeStamp($nonce, $timestamp, OAuthConsumer $consumer, OAuthToken $token = NULL);
	abstract public function addTempToken(OAuthConsumer $consumer, OAuthToken $new_token, $callback_url);
	abstract public function checkTempToken(OAuthConsumer $consumer, $token_str, $callback_url, $user_idf, $authed_status, &$token_secret);
	abstract public function authorizeTempToken($token_str, $user_idf, $verifier);
	abstract public function deleteTempToken($token_str, $user_idf);
	abstract public function getTempTokenCallback(token_str, $user_idf);
	abstract public function generateVerifier($callback_url);
	abstract public function exchangeTempToken(OAuthConsumer $consumer, OAuthToken $temp_token, OAuthToken $new_token);
	abstract public function getAccessTokenInfo(OAuthConsumer $consumer, $token_str, &$token_secret, &$user_data);
}

