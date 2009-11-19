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

	/**
	 * test taken from http://oauth.googlecode.com/svn/code/php/tests/OAuthUtilTest.php mostly.
	 **/
	public function testUrlencode()
	{
		// Tests taken from
		// http://wiki.oauth.net/TestCases ("Parameter Encoding")
		$this->assertEquals('abcABC123', OAuthUtil::urlEncode('abcABC123'));
		$this->assertEquals('-._~',      OAuthUtil::urlEncode('-._~'));
		$this->assertEquals('%25',       OAuthUtil::urlEncode('%'));
		$this->assertEquals('%2B',       OAuthUtil::urlEncode('+'));
		$this->assertEquals('%0A',       OAuthUtil::urlEncode("\n"));
		$this->assertEquals('%20',       OAuthUtil::urlEncode(' '));
		$this->assertEquals('%7F',       OAuthUtil::urlEncode("\x7F"));
		$this->assertEquals('%C2%80',    OAuthUtil::urlEncode(mb_convert_encoding(pack('n', 0x0080), 'UTF-8', 'UTF-16')));
		$this->assertEquals('%E3%80%81', OAuthUtil::urlEncode(mb_convert_encoding(pack('n', 0x3001), 'UTF-8', 'UTF-16')));
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testUrlencode2()
	{
		OAuthUtil::urlEncode(NULL);
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testUrlencode3()
	{
		OAuthUtil::urlEncode(new stdClass());
	}

	public function testUrldecode()
	{
		// Tests taken from
		// http://wiki.oauth.net/TestCases ("Parameter Encoding")
		$this->assertEquals('abcABC123', OAuthUtil::urlDecode('abcABC123'));
		$this->assertEquals('-._~',      OAuthUtil::urlDecode('-._~'));
		$this->assertEquals('%',         OAuthUtil::urlDecode('%25'));
		$this->assertEquals('+',         OAuthUtil::urlDecode('%2B'));
		$this->assertEquals("\n",        OAuthUtil::urlDecode('%0A'));
		$this->assertEquals(' ',         OAuthUtil::urlDecode('%20'));
		$this->assertEquals("\x7F",      OAuthUtil::urlDecode('%7F'));
		$this->assertEquals(mb_convert_encoding(pack('n', 0x0080), 'UTF-8', 'UTF-16'),  OAuthUtil::urlDecode('%C2%80'));
		$this->assertEquals(mb_convert_encoding(pack('n', 0x3001), 'UTF-8', 'UTF-16'),  OAuthUtil::urlDecode('%E3%80%81'));
	}
}
