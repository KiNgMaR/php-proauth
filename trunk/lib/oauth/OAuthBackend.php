<?php

abstract class OAuthBackend
{
	abstract public function getConsumerByKey($consumer_key);
	abstract public function checkNonceAndTimeStamp($nonce, $timestamp, OAuthConsumer $consumer, OAuthToken $token);
}

?>