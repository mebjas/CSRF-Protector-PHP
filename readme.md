CSRF Protector
==========================
CSRF protector php, a standalone php library for csrf mitigation in web applications.

How to use
==========
```php
<?php
include_once __DIR__ .'/libs/csrf/csrfprotector.php';

//Initialise CSRFGuard library
csrfProtector::init();
```
simply include the library and call the `init()` function!
