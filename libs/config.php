<?php
/**
 * Configuration file for CSRF Protector z
 */
return array(
	"isLoggingEnabled" => true,
	"logDirectory" => "../log",
	"failedAuthAction" => 0,
	"errorRedirectionPage" => "http://localhost/",
	"customErrorMessage" => "",
	"jsFile" => "http://localhost/test/csrf/js/csrfprotector.js",
	"tokenLength" => 32
);