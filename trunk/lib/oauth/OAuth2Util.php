<?php

class OAuth2Exception extends Exception
{
	protected $error_idf;

	public function __construct($error_msg, $error_idf = '')
	{
		parent::__construct($error_msg);

		$this->error_idf = $error_idf;
	}

}


class OAuth2AccessToken
{

}

