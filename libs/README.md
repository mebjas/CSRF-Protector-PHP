CSRFProtector configuration
==========================================

`isGETEnabled` `boolean` variable to check if validation should be done for GET requests or not<br>
`logDirectory` `string` log file directory with respect to `/libs/`<br>
>for example, if the library is present at /x/y/ and config file at /x/y/libs/config.php<br>
> `../logs/` would mean `/x/logs/`

`failedAuthAction` `int` action to be taken in case of a failed validation for CSRF<br> 
> `failedAuthAction = 0` Send 403, Forbidden Header<br>
> `failedAuthAction = 1` strip the POST/GET query and forward the request! `unset($_POST)`<br>
> `failedAuthAction = 2` Redirect to custom error page mentioned in `errorRedirectionPage` <br>
> `failedAuthAction = 3` Show custom error message to user <br>
> `failedAuthAction = 4` Send 500, Internal Server header<br>

**Default values for `failedAuthAction`**<br>
--for **POST**: `0`<br>
--for **GET**: `1`<br> 

`errorRedirectionPage` `string` **absolute url** of custom error page<br>
`customErrorMessage` `string` Custom error message to be shown in case `failedAuthAction = 3`<br>
`jsFile` `string` url of the javascript file, for example `http://yoursite.com/csrfp/js/csrfprotector.js`<br>
`tokenLength` `int` length of CSRFProtector Auth Token<br>
`disabledJavascriptMessage` `string` Error message to be shown to users, incase js is disabled in user browser
