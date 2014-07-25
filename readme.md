CSRF Protector
==========================
[![Build Status](https://travis-ci.org/mebjas/CSRF-Protector-PHP.svg?branch=nojs-support)](https://travis-ci.org/mebjas/CSRF-Protector-PHP) [![Coverage Status](https://coveralls.io/repos/mebjas/CSRF-Protector-PHP/badge.png?branch=nojs-support)](https://coveralls.io/r/mebjas/CSRF-Protector-PHP?branch=master)
<br>CSRF protector php, a standalone php library for csrf mitigation in web applications. Easy to integrate in any php web app.


Note
==========
this version supports noJs, however we have a version for js only applications. If your application requires the user to have js enabled, use the js version. [Check how js version is better](https://github.com/mebjas/CSRF-Protector-PHP/wiki/js-version-versus-nojs-version) 

[Link to js version](https://github.com/mebjas/CSRF-Protector-PHP/)


How to use
==========
```php
<?php
include_once __DIR__ .'/libs/csrf/csrfprotector.php';

//Initialise CSRFGuard library
csrfProtector::init();
```
simply include the library and call the `init()` function!

###Detailed information @[Project wiki on github](https://github.com/mebjas/CSRF-Protector-PHP/wiki)

###Contribute

* Fork the repo
* Create your branch
* Commit your changes
* Create a pull request

More information @[OWASP wiki](https://www.owasp.org/index.php/CSRFProtector_Project)
====================

##Join Discussions on mailing list
[link to mailing list](https://lists.owasp.org/mailman/listinfo/owasp-csrfprotector)

for any other queries contact me at: **minhaz@owasp.org**
