CSRF Protector
==========================
[![Build Status](https://travis-ci.org/mebjas/CSRF-Protector-PHP.svg?branch=master)](https://travis-ci.org/mebjas/CSRF-Protector-PHP) [![Coverage Status](https://coveralls.io/repos/mebjas/CSRF-Protector-PHP/badge.png?branch=master)](https://coveralls.io/r/mebjas/CSRF-Protector-PHP?branch=master)
<br>CSRF protector php, a standalone php library for csrf mitigation in web applications. Easy to integrate in any php web app.

How to use
==========
```php
<?php
include_once __DIR__ .'/libs/csrf/csrfprotector.php';

//Initialise CSRFGuard library
csrfProtector::init();
```
simply include the library and call the `init()` function!

###Contribute

* Fork the repo
* Create your branch
* Commit your changes
* Create a pull request


##Join Discussions on mailing list
[link to mailing list](https://lists.owasp.org/mailman/listinfo/owasp-csrfprotector)

for any other queries contact me at: **minhaz@owasp.org**
