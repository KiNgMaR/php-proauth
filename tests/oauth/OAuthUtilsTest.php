<?php

require_once '../../lib/oauth/OAuthUtil.php';
require_once 'PHPUnit/Framework.php';

class OAuthUtilsTest extends PHPUnit_Framework_TestCase
{
	public function testGetIfSet()
	{
		$arr = array();
		$no_arr = 'hi!';

		$this->assertEquals(OAuthUtil::getIfSet($arr, 'x', 'default'), 'default');
		$this->assertEquals(OAuthUtil::getIfSet($arr, 'x'), NULL);
		$this->assertEquals(OAuthUtil::getIfSet($no_var, 'x', 'default'), 'default');
		$this->assertEquals(OAuthUtil::getIfSet($no_arr, 'x', 'default'), 'default');

		$arr['x'] = '';
		$this->assertEquals(OAuthUtil::getIfSet($arr, 'x', 'default'), 'default');

		$arr['x'] = 'w00t';
		$this->assertEquals(OAuthUtil::getIfSet($arr, 'x', 'default'), 'w00t');
	}
}
