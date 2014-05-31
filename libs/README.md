CSRFProtector configuration
==========================================

`logDirectory` `string` log file directory with respect to `/libs/`<br>
>for example, if the library is present at /x/y/ and config file at /x/y/libs/config.php<br>
> `../logs/` would mean `/x/logs/`

`failedAuthAction` `int array` action to be taken in case of a failed validation for CSRF<br> 
1. Send 403, Forbidden Header<br>
2. Strip the POST/GET query and forward the request! `unset($_POST)`<br>
3. Redirect to custom error page mentioned in `errorRedirectionPage` <br>
4. Show custom error message to user <br>
5. Send 500, Internal Server header<br>

**Default values for `failedAuthAction`** for **POST or GET**: `0`<br>

`errorRedirectionPage` `string` **absolute url** of custom error page<br>
`customErrorMessage` `string` Custom error message to be shown in case `failedAuthAction = 3`<br>
`jsFile` `string` url of the javascript file, for example `http://yoursite.com/csrfp/js/csrfprotector.js`<br>
`tokenLength` `int` length of CSRFProtector Auth Token<br>
`disabledJavascriptMessage` `string` Error message to be shown to users, incase js is disabled in user browser<br>

`verifyGetFor` `string array` files matching the urls, in this array will be validated for GET CSRF attacks
```php
*://*/* matches every url
*://example.com/user/delete.php matches this document for any protocol
http://example.com/* matches every http GET requests
```
