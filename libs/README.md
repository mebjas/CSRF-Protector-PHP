CSRFProtector configuration
==========================================

`logDirectory` `string` log file directory with respect to `/libs/`<br>
>for example, if the library is present at /x/y/ and config file at /x/y/libs/config.php<br>
> `../logs/` would mean `/x/logs/`

`failedAuthAction` `int` action to be taken in case of a failed validation for CSRF<br> 
> `failedAuthAction = 0` strip the POST query and forward the request! `unset($_POST)`<br>
> `failedAuthAction = 1` Send 404, Not Found Header<br>
> `failedAuthAction = 2` Send 403, Forbidden Header<br>
> `failedAuthAction = 3` Show custom error message to user <br>
> `failedAuthAction = 4` Redirect to custom error page mentioned in `errorRedirectionPage` <br>

`errorRedirectionPage` `string` **absolute url** of custom error page<br>
`customErrorMessage` `string` Custom error message to be shown in case `failedAuthAction = 3`<br>
`jsFile` `string` url of the javascript file, for example `http://yoursite.com/csrfp/js/csrfprotector.js`<br>
`tokenLength` `int` length of CSRFProtector Auth Token<br>
`disabledJavascriptMessage` `string` Error message to be shown to users, incase js is disabled in user browser
