<?php

class configFileNotFoundException extends \exception {};
class logDirectoryNotFoundException extends \exception {};
class jsFileNotFoundException extends \exception {};

class csrfProtector
{
	/**
	 * Name of the token sent to client as cookie and
	 * sent from client as post
	 * NOTE: DO NOT CHANGE THIS
	 */
	public static $tokenName = 'CSRF_AUTH_TOKEN';

	/**
	 * expiry time for cookie
	 */
	public static $cookieExpiryTime = 300;	//5 minutes

	/**
	 * flag for cross origin/same origin request
	 */
	public static $isSameOrigin = true;	//5 minutes

	/**
	 * flag to check if output file is a valid HTML or not
	 */
	private static $isValidHTML = false;

	/**
	 * config file for CSRFProtector
	 * #Array, length = 4
	 * @property #1: isLoggingEnabled (bool) => true if logging is allowed, false otherwise
	 * @property #2: failedAuthAction (int) => action to be taken in case autherisation fails
	 * @property #3: logDirectory (string) => directory in which log will be saved
	 * @property #4: customErrorMessage (string) => custom error message to be sent in case
	 *												of failed authentication
	 * @property #5: jsFile (string) => location of the CSRFProtector js file
	 */
	private static $config = array();

	/**
	 * function to initialise the csrfProtector work flow
	 */
	public static function initialise($logging = null, $action = null)
	{
		if (!file_exists(__DIR__ ."/../config.php")) {
			throw new configFileNotFoundException("configuration file not found for CSRFProtector!");	
		}

		//load configuration file and properties
		self::$config = include(__DIR__ ."/../config.php");

		//loading logging property
		if ($logging !== null) {
			self::$config['isLoggingEnabled'] = $logging;
		}
		
		//action that is needed to be taken in case of failed authorisation
		if ($action !== null) {
			self::$config['failedAuthAction'] = $action;
		}	

		//authorise the incoming request
		self::authorisePost();

		// Initialize our handler
		ob_start('csrfProtector::ob_handler');
	}

	/**
	 * function to authorise incoming post requests
	 */
	public static function authorisePost($logging = true, $action = 0)
	{
		//#todo this method is valid for same origin request only
		//for cross origin the functionality is different
		if ($_SERVER['REQUEST_METHOD'] === 'POST') {

			//currently for same origin only
			if (!(isset($_POST['CSRFPROTECTOR_AUTH_TOKEN']) 
				&& isset($_COOKIE[self::$tokenName])
				&& ($_POST['CSRFPROTECTOR_AUTH_TOKEN'] === $_COOKIE[self::$tokenName])
				)) {

				if(self::$config['isLoggingEnabled']) {
					if (!file_exists(__DIR__ .self::$config['isLoggingEnabled'])) {
						throw new logDirectoryNotFoundException("Log Directory Not Found!");		
					}
				}

				//#todo: ask mentors if $failedAuthAction is better as an int or string
				//default case is case 0
				switch (self::$config['failedAuthAction']) {
					case 1:
						//show 404
						header("HTTP/1.0 404 Not Found");
						exit("<h2>404 Not Found!</h2>");
					case 2:
						//show 403
						header('HTTP/1.0 403 Forbidden');
						exit("<h2>403 Access Forbidden by CSRFProtector!</h2>");
					case 3:
						//custom error message
						exit(self::$config['customErrorMessage']);
					default:
						unset($_POST);
						break;
				}					
			}
		} 

		/**
		 * in case cookie exist -> refresh it
		 * else create one
		 */
		self::refreshCookie();	
	}

	/**
	 * function to refresh cookie sent to browser
	 * @param: void
	 */
	public static function refreshCookie()
	{
		if (!isset($_COOKIE[self::$tokenName])) {
			self::createCookie();
		} else {
			//reset the cookie to a longer period
			setcookie(self::$tokenName, 
				$_COOKIE[self::$tokenName], 
				time() + self::$cookieExpiryTime);
		}
	}

	/**
	 * function to set auth cookie 
	 * @param: void
	 */
	public static function createCookie()
	{
		setcookie(self::$tokenName, 
			self::generateAuthToken(), 
			time() + self::$cookieExpiryTime);
	}

	/**
	 * function to generate random hash of length as given in parameter
	 * max length = 128
	 * @param: length to hash required, int
	 */
	public static function generateAuthToken($length = 64)
	{
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
		return substr($token, 0, $length);
	}

	/**
	 * Rewrites <form> on the fly to add CSRF tokens to them. This can also
	 * inject our JavaScript library.
	 * @param: $buffer, output buffer to which all output are stored
	 * @param: flag
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
		
	    /*
	    //you can add code to check if js file exists
	    if (!file_exists(self::$config['jsFile'])) {
	        $buffer = "CSRFProtector js file not found at " .self::$config['jsFile'] ." in " 
	        .__FILE__ ." on line " .__LINE__;
	        return $buffer;
	    }
	    */
	    $script = '<script type="text/javascript" src="' .self::$config['jsFile'] .'"></script>';	

	    //implant the CSRFGuard js file to outgoing script
	    $buffer = str_ireplace('</body>', $script . '</body>', $buffer, $count);
	    if (!$count) {
	        $buffer .= $script;
	    }

	    return $buffer;
	}
};

