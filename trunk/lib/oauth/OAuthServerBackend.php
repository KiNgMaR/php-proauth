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
	public const RESULT_OPERATION_NOT_PETMITTED = 9;

	/**
	 * @param string consumer_key
	 * @return mixed Return an OAuthConsumer instance, or one of: RESULT_RATE_LIMITED, RESULT_DISABLED, RESULT_NOT_FOUND
	 **/
	abstract public function getConsumerByKey($consumer_key);

	/**
	 * @return int One of: RESULT_OK, RESULT_DUPE_NONCE, RESULT_BAD_TIMESTAMP, RESULT_BAD_TOKEN
	 **/
	abstract public function checkNonceAndTimeStamp($nonce, $timestamp, OAuthConsumer $consumer, OAuthToken $token = NULL);

	/**
	 * Creates a new temporary token/key pair, associated with $consumer and optionally $callback_url.
	 * @return int One of: RESULT_DUPE (the token string is already used), RESULT_OK
	 **/
	abstract public function addTempToken(OAuthConsumer $consumer, OAuthToken $new_token, $callback_url);

	/**
	 * @return int Return RESULT_OK or RESULT_ERROR.
	 **/
	abstract public function checkTempToken(OAuthConsumer $consumer, $token_str, $callback_url, $user_idf, $authed_status, &$token_secret);

	/**
	 * If authorizing the temp token succeeded, the backend can set $redirect = true to redirect
	 * to the callback URL or display the verifier to the user using other means (with $redirect = false).
	 * @return int Return RESULT_OK or RESULT_ERROR.
	 **/
	abstract public function authorizeTempToken($token_str, $user_idf, $verifier, &$redirect);

	/**
	 * @return int Return RESULT_OK or RESULT_ERROR.
	 **/
	abstract public function deleteTempToken($token_str, $user_idf);

	/**
	 * @return string
	 **/
	abstract public function getTempTokenCallback($token_str, $user_idf);

	/**
	 * @return string
	 **/
	abstract public function generateVerifier($callback_url);

	/**
	 * @return int Return RESULT_OK or RESULT_ERROR.
	 **/
	abstract public function getVerifierParameter($token_str, $verifier);

	/**
	 * @return int One of: RESULT_DUPE (the token string is already used), RESULT_OK
	 **/
	abstract public function exchangeTempToken(OAuthConsumer $consumer, OAuthToken $temp_token, OAuthToken $new_token);

	/**
	 * @return int Return RESULT_OK or RESULT_ERROR.
	 **/
	abstract public function getAccessTokenInfo(OAuthConsumer $consumer, $token_str, &$token_secret, &$user_data);
}

