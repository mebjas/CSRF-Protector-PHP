<?php

//name of HTTP POST variable for authentication
define("CSRFP_TOKEN","csrfp_token");

/**
 * child exception classes
 */
class configFileNotFoundException extends \exception {};
class logDirectoryNotFoundException extends \exception {};
class jsFileNotFoundException extends \exception {};
class logFileWriteError extends \exception {};
class baseJSFileNotFoundExceptio extends \exception {};
class incompleteConfigurationException extends \exception {};

class csrfProtector
{
	/*
	 * Variable: $cookieExpiryTime
	 * expiry time for cookie
	 * @var int
	 */
	public static $cookieExpiryTime = 1800;	//30 minutes

	/*
	 * Variable: $isSameOrigin
	 * flag for cross origin/same origin request
	 * @var bool
	 */
	private static $isSameOrigin = true;

	/*
	 * Variable: $isValidHTML
	 * flag to check if output file is a valid HTML or not
	 * @var bool
	 */
	private static $isValidHTML = false;

	/*
	 * Variable: $requestType
	 * Varaible to store weather request type is post or get
	 * @var string
	 */
	protected static $requestType = "GET";

	/*
	 * Variable: tokenExpiryTime
	 * time after which the token shall expire if not the last
	 * set token
	 */
	private static $tokenExpiryTime = 60;	// 60 seconds

	/*
	 * Variable: $config
	 * config file for CSRFProtector
	 * @var int Array, length = 6
	 * Property: #1: failedAuthAction (int) => action to be taken in case autherisation fails
	 * Property: #2: logDirectory (string) => directory in which log will be saved
	 * Property: #3: customErrorMessage (string) => custom error message to be sent in case
	 *						of failed authentication
	 * Property: #4: jsFile (string) => location of the CSRFProtector js file
	 * Property: #5: tokenLength (int) => default length of hash
	 * Property: #6: disabledJavascriptMessage (string) => error message if client's js is disabled
	 */
	public static $config = array();

	/*
	 * Variable: $requiredConfigurations
	 * Contains list of those parameters that are required to be there
	 * 	in config file for csrfp to work
	 */
	public static $requiredConfigurations  = array('logDirectory', 'failedAuthAction', 'jsPath', 'jsUrl', 'tokenLength');
	
	/*
	 *	Function: init
 	 *
	 *	function to initialise the csrfProtector work flow
	 *
	 *	Parameters:
	 *	$length - length of CSRF_AUTH_TOKEN to be generated
	 *	$action - int array, for different actions to be taken in case of failed validation
	 *
	 *	Returns:
	 *		void
	 *
	 *	Throws:
	 *		configFileNotFoundException - when configuration file is not found
	 * 		incompleteConfigurationException - when all required fields in config
	 *											file are not available
	 *
	 */
	public static function init($length = null, $action = null)
	{
		/*
		 * if mod_csrfp already enabled, no verification, no filtering
		 * Already done by mod_csrfp
		 */
		if (getenv('mod_csrfp_enabled'))
			return;

		//start session in case its not
		if (session_id() == '')
		    session_start();

		if (!file_exists(__DIR__ ."/../config.php"))
			throw new configFileNotFoundException("OWASP CSRFProtector: configuration file not found for CSRFProtector!");	

		//load configuration file and properties
		self::$config = include(__DIR__ ."/../config.php");

		//overriding length property if passed in parameters
		if ($length != null)
			self::$config['tokenLength'] = intval($length);
		
		//action that is needed to be taken in case of failed authorisation
		if ($action != null)
			self::$config['failedAuthAction'] = $action;

		if (self::$config['CSRFP_TOKEN'] == '')
			self::$config['CSRFP_TOKEN'] = CSRFP_TOKEN;

		// Validate the config if everythings filled out
		foreach (self::$requiredConfigurations as $value) {
			if (!isset(self::$config[$value]) || self::$config[$value] == '') {
				throw new incompleteConfigurationException("OWASP CSRFProtector: Incomplete configuration file!");
				exit;
			}
		}

		// Authorise the incoming request
		self::authorizePost();

		// Initialize output buffering handler
		ob_start('csrfProtector::ob_handler');

		if (!isset($_COOKIE[self::$config['CSRFP_TOKEN']])
			|| !isset($_SESSION[self::$config['CSRFP_TOKEN']][0])
			|| ($_COOKIE[self::$config['CSRFP_TOKEN']] != 
				$_SESSION[self::$config['CSRFP_TOKEN']]][count(
					$_SESSION[self::$config['CSRFP_TOKEN']]) - 1][0]
				))
			self::refreshToken();
	}

	/*
	 * Function: useCachedVersion
	 * function to check weather to use cached version of js
	 * 		file or not
	 *
	 * Parameters:
	 *  void
	 *
	 * Returns:
	 * bool -- true if cacheversion can be used
	 *					-- false otherwise
	 */
	public static function useCachedVersion()
	{
		$configLastModified = filemtime(__DIR__ ."/../config.php");
		if (file_exists(__DIR__ ."/../" .self::$config['jsPath'])) {
			$jsFileLastModified = filemtime(__DIR__ ."/../" 
				.self::$config['jsPath']);
			if ($jsFileLastModified < $configLastModified) {
				// -- config is more recent than js file
				return false;
			}
			return true;
		} else
			return false;
		
	}

	/*
	 * Function: createNewJsCache
	 * Function to create new cache version of js
	 *
	 * Parameters:
	 * void
	 *
	 * Returns:
	 * void
	 *
	 * Throws:
	 * baseJSFileNotFoundExceptio - if baseJsFile is not found
	 */
	public static function createNewJsCache()
	{
		if (!file_exists(__DIR__ ."/csrfpJsFileBase.php")) {
			throw new baseJSFileNotFoundExceptio("OWASP CSRFProtector: base js file needed to create js file not found at " .__DIR__);
			return;
		}

		$jsFile = file_get_contents(__DIR__ ."/csrfpJsFileBase.php");
		$arrayStr = '';
		if (self::$config['verifyGetFor']) {
			foreach (self::$config['verifyGetFor'] as $key => $value) {
				if ($key != 0) $arrayStr .= ',';
				$arrayStr .= "'". $value ."'";
			}
		}
		$jsFile = str_replace('$$tokenName$$', self::$config['CSRFP_TOKEN'], $jsFile);
		$jsFile = str_replace('$$getAllowedUrls$$', $arrayStr, $jsFile);
		file_put_contents(__DIR__ ."/../" .self::$config['jsPath'], $jsFile);
	}

	/*
	 * Function: validateToken
	 * function to validatet the token with ones in session
	 *
	 * Parameters:
	 * $token - token to compare with
	 *
	 * Returns:
	 * $flag - (bool) true for passed validation false otherwise
	 */
	private static function validateToken($token) {
		$flag = false;
		$MAX = count($_SESSION[self::$config['CSRFP_TOKEN']]);

		foreach ($_SESSION[self::$config['CSRFP_TOKEN']] as $key => $value) {
			// [0] is the value
			// [1] is the timestamp
			if ($token == $value[0]
				&& (intval($value[1]) >= time() - self::$tokenExpiryTime
					|| $key == $MAX - 1)) {
				$flag = true;
				break;
			}
		}

		//Clear old tokens
		$tempSessionArray = array();
		foreach ($_SESSION[self::$config['CSRFP_TOKEN']] as $key => $value) {
			if (intval($value[1]) >= time() - self::$tokenExpiryTime
				|| $key == $MAX - 1) {
				array_push($tempSessionArray, $value);
			}
		}

		$_SESSION[self::$config['CSRFP_TOKEN']] = $tempSessionArray;
		return $flag;
	}

	/*
	 * Function: authorizePost
	 * function to authorise incoming post requests
	 *
	 * Parameters: 
	 * void
	 *
	 * Returns: 
	 * void
	 *
	 * Throws: 
	 * logDirectoryNotFoundException - if log directory is not found
	 */
	public static function authorizePost()
	{
		//#todo this method is valid for same origin request only, 
		//enable it for cross origin also sometime
		//for cross origin the functionality is different
		if ($_SERVER['REQUEST_METHOD'] === 'POST') {

			//set request type to POST
			self::$requestType = "POST";

			//currently for same origin only
			if (!(isset($_POST[self::$config['CSRFP_TOKEN']]) 
				&& isset($_SESSION[self::$config['CSRFP_TOKEN']])
				&& self::validateToken($_POST[self::$config['CSRFP_TOKEN']])
				)) {

				//action in case of failed validation
				self::failedValidationAction();			
			} else {
				self::refreshToken();	//refresh token for successfull validation
			}
		} else if (!static::isURLallowed()) {
			
			//currently for same origin only
			if (!(isset($_GET[self::$config['CSRFP_TOKEN']]) 
				&& isset($_SESSION[self::$config['CSRFP_TOKEN']])
				&& self::validateToken($_GET[self::$config['CSRFP_TOKEN']])
				)) {

				//action in case of failed validation
				self::failedValidationAction();			
			} else {
				self::refreshToken();	//refresh token for successfull validation
			}
		}	
	}

	/*
	 * Function: failedValidationAction
	 * function to be called in case of failed validation
	 * performs logging and take appropriate action
	 *
	 * Parameters: 
	 * void
	 *
	 * Returns: 
	 * void
	 */
	private static function failedValidationAction()
	{
		if (!file_exists(__DIR__ ."/../" .self::$config['logDirectory']))
			throw new logDirectoryNotFoundException("OWASP CSRFProtector: Log Directory Not Found!");
	
		//call the logging function
		static::logCSRFattack();

		//#todo: ask mentors if $failedAuthAction is better as an int or string
		//default case is case 0
		switch (self::$config['failedAuthAction'][self::$requestType]) {
			case 0:
				//send 403 header
				header('HTTP/1.0 403 Forbidden');
				exit("<h2>403 Access Forbidden by CSRFProtector!</h2>");
				break;
			case 1:
				//unset the query parameters and forward
				if (self::$requestType === 'GET') {
					$_GET = array();
				} else {
					$_POST = array();
				}
				break;
			case 2:
				//redirect to custom error page
				$location  = self::$config['errorRedirectionPage'];
				header("location: $location");
			case 3:
				//send custom error message
				exit(self::$config['customErrorMessage']);
				break;
			case 4:
				//send 500 header -- internal server error
				header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error', true, 500);
				exit("<h2>500 Internal Server Error!</h2>");
				break;
			default:
				//unset the query parameters and forward
				if (self::$requestType === 'GET') {
					$_GET = array();
				} else {
					$_POST = array();
				}
				break;
		}		
	}

	/*
	 * Function: refreshToken
	 * Function to set auth cookie
	 *
	 * Parameters: 
	 * void
	 *
	 * Returns: 
	 * void
	 */
	public static function refreshToken()
	{
		$token = self::generateAuthToken();
		$index  = 0;

		//set token to session for server side validation
		(isset($_SESSION[self::$config['CSRFP_TOKEN']])) ?
			$index = count($_SESSION[self::$config['CSRFP_TOKEN']]) :
			$_SESSION[self::$config['CSRFP_TOKEN']] = array();
		
		if ($index == 0)
			$_SESSION[self::$config['CSRFP_TOKEN']] = array();

		$_SESSION[self::$config['CSRFP_TOKEN']][$index] = array(
			0 => $token,
			1 => time());

		//set token to cookie for client side processing
		setcookie(self::$config['CSRFP_TOKEN'], 
			$token, 
			time() + self::$cookieExpiryTime);
	}

	/*
	 * Function: generateAuthToken
	 * function to generate random hash of length as given in parameter
	 * max length = 128
	 *
	 * Parameters: 
	 * length to hash required, int
	 *
	 * Returns:
	 * string, token
	 */
	public static function generateAuthToken()
	{
		//if config tokenLength value is 0 or some non int
		if (intval(self::$config['tokenLength']) == 0) {
			self::$config['tokenLength'] = 32;	//set as default
		}

		//if $length > 128 throw exception #todo 

		if (function_exists("hash_algos") && in_array("sha512", hash_algos())) {
			$token = hash("sha512", mt_rand(0, mt_getrandmax()));
		} else {
			$token = '';
			for ($i = 0; $i < 128; ++$i) {
				$r = mt_rand(0, 35);
				if ($r < 26) {
					$c = chr(ord('a') + $r);
				} else { 
					$c = chr(ord('0') + $r - 26);
				}
				$token .= $c;
			}
		}
		return substr($token, 0, self::$config['tokenLength']);
	}

	/*
	 * Function: ob_handler
	 * Rewrites <form> on the fly to add CSRF tokens to them. This can also
	 * inject our JavaScript library.
	 *
	 * Parameters: 
	 * $buffer - output buffer to which all output are stored
	 * $flag - INT
	 *
	 * Return:
	 * string, complete output buffer
	 */
	public static function ob_handler($buffer, $flags)
	{
		// Even though the user told us to rewrite, we should do a quick heuristic
	    // to check if the page is *actually* HTML. We don't begin rewriting until
	    // we hit the first <html tag.
	    if (!self::$isValidHTML) {
	        // not HTML until proven otherwise
	        if (stripos($buffer, '<html') !== false) {
	            self::$isValidHTML = true; 
	        } else {
	            return $buffer;
	        }
	    }
	    
	    //add a <noscript> message to outgoing HTML output,
	    //informing the user to enable js for CSRFProtector to work
	    //best section to add, after <body> tag
	    $buffer = preg_replace("/<body[^>]*>/", "$0 <noscript>" .self::$config['disabledJavascriptMessage'] .
	    	"</noscript>", $buffer);

	    $arrayStr = '';
	    if (!self::useCachedVersion()) {
	    	try {
	    		self::createNewJsCache();
	    	} catch (exception $ex) {
	    		if (self::$config['verifyGetFor']) {
					foreach (self::$config['verifyGetFor'] as $key => $value) {
						if ($key != 0) $arrayStr .= ',';
						$arrayStr .= "'". $value ."'";
					}
				}
	    	}
	    }

	    $script = '<script type="text/javascript" src="' .self::$config['jsUrl']
	    	.'"></script>' .PHP_EOL;

	    $script .= '<script type="text/javascript">' .PHP_EOL;
	    if ($arrayStr !== '') {
	    	$script .= 'CSRFP.checkForUrls = [' .$arrayStr .'];' .PHP_EOL;
	    }
	    $script .= 'window.onload = function() {' .PHP_EOL;
	    $script .= '	csrfprotector_init();' .PHP_EOL;
	    $script .= '};' .PHP_EOL;
	    $script .= '</script>' .PHP_EOL;

	    //implant the CSRFGuard js file to outgoing script
	    $buffer = str_ireplace('</body>', $script . '</body>', $buffer, $count);
	    if (!$count)
	        $buffer .= $script;

	    return $buffer;
	}

	/*
	 * Function: logCSRFattack
	 * Functio to log CSRF Attack
	 * 
	 * Parameters: 
	 * void
	 *
	 * Retruns: 
	 * void
	 *
	 * Throws: 
	 * logFileWriteError - if unable to log an attack
	 */
	private static function logCSRFattack()
	{
		//if file doesnot exist for, create it
		$logFile = fopen(__DIR__ ."/../" .self::$config['logDirectory']
		."/" .date("m-20y") .".log", "a+");
		
		//throw exception if above fopen fails
		if (!$logFile)
			throw new logFileWriteError("OWASP CSRFProtector: Unable to write to the log file");	

		//miniature version of the log
		$log = array();
		$log['timestamp'] = time();
		$log['HOST'] = $_SERVER['HTTP_HOST'];
		$log['REQUEST_URI'] = $_SERVER['REQUEST_URI'];
		$log['requestType'] = self::$requestType;

		if (self::$requestType === "GET")
			$log['query'] = $_GET;
		else
			$log['query'] = $_POST;

		$log['cookie'] = $_COOKIE;

		//convert log array to JSON format to be logged
		$log = json_encode($log) .PHP_EOL;

		//append log to the file
		fwrite($logFile, $log);

		//close the file handler
		fclose($logFile);
	}

	/*
	 * Function: getCurrentUrl
	 * Function to return current url of executing page
	 * 
	 * Parameters: 
	 * void
	 *
	 * Returns: 
	 * string - current url
	 */
	private static function getCurrentUrl()
	{
		return $_SERVER['REQUEST_SCHEME'] .'://'
			.$_SERVER['HTTP_HOST'] .$_SERVER['PHP_SELF'];
	}

	/*
	 * Function: isURLallowed
	 * Function to check if a url mataches for any urls
	 * Listed in config file
	 *
	 * Parameters: 
	 * void
	 *
	 * Returns: 
	 * boolean - true is url need no validation, false if validation needed
	 */  
	public static function isURLallowed() {
		foreach (self::$config['verifyGetFor'] as $key => $value) {
			$value = str_replace(array('/','*'), array('\/','(.*)'), $value);
			preg_match('/' .$value .'/', self::getCurrentUrl(), $output);
			if (count($output) > 0)
				return false;
		}
		return true;
	}
};
