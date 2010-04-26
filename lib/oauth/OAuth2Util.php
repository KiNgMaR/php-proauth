<?php
/*
 * php-proauth (c) Ingmar "KiNgMaR" Runge 2009-2010
 * You are free to use this code under the terms of The MIT License.
 * You should have received a copy of The MIT License in LICENSE.txt with this file.
 */

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

