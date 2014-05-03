CSRFProtector configuration
==========================================


`isLoggingEnabled` `bool` true if every failed validation for CSRF should be logged!<br>
`logDirectory` `string` log file directory with respect to `/libs/csrf/`<br>
`failedAuthAction` `int` action to be taken in case of a failed validation for CSRF<br> 
> `failedAuthAction = 0` strip the POST query and forward the request! `unset($_POST)`<br>
> `failedAuthAction = 1` Send 404, Not Found Header<br>
> `failedAuthAction = 2` Send 403, Forbidden Header<br>
> `failedAuthAction = 3` Show custom error message to user <br>

`customErrorMessage` `string` Custom error message to be shown in case `failedAuthAction = 3`<br>
`jsFile` `string` url of the javascript file `http://yoursite.com/csrfp/js/csrfprotector.js`
