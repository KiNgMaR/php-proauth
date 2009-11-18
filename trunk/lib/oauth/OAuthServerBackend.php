<?php

abstract class OAuthServerBackend
{
	abstract public function getConsumerByKey($consumer_key);
	abstract public function checkNonceAndTimeStamp($nonce, $timestamp, OAuthConsumer $consumer, OAuthToken $token);
}

?>