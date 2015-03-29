There are quite a number of OAuth libraries for PHP already. However, all of those suffer from some weaknesses, such as lack of 1.0a support, bad coding style, missing documentation and/or lack of updates.

This library is an attempt to fix those shortcomings and to make it as easy as possible to use OAuth in PHP, for both OAuth Providers and Consumers.

Contributions and patches are VERY welcome. Just leave a note in the issue tracker and I'll assign the necessary commit permissions to your account!

### Features ###
  * Easy-to-use library for Service Providers/servers
  * Carefully designed around the OAuth Core specs submitted to the IETF
  * Classy client/Consumer library
  * Well documented and tested (not yet!)

### Limitations ###
  * No support for multiple parameters of the same name (intentional)
  * No support for file uploads signed with OAuth yet.

### Important ###
  * Includes an OAuth 2.0 client library
  * more TBA (better test suite, improved docs & examples, OAuth 2.0 server library)
  * The OAuth2 client library is not up with the latest specification draft... it works with Facebook though. It will be updated once OAuth 2 has reached final status.

### Requirements ###
  * PHP 5.2 or 5.3.