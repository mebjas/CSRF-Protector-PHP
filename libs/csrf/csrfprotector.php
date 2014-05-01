<?php

class csrfProtector
{
	/**
	 * Name of the cookie sent to client
	 */
	public static $cookieName = 'CSRF_AUTH_TOKEN';

	/**
	 * Name of the POST variable sent from client
	 */
	public static $postName = 'CSRF_AUTH_TOKEN';

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
	 * function to initialise the csrfProtector work flow
	 */
	public static function initialise()
	{
		//authorise the incoming request
		self::authorisePost();

		// Initialize our handler
		ob_start('csrfProtector::ob_handler');	
		//#todo: feature to not run this when required
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
			if (!(isset($_POST[self::$postName]) 
				&& isset($_COOKIE[self::$cookieName])
				&& ($_POST[self::$postName] === $_COOKIE[self::$cookieName])
				)) {

				if($logging) {
					//#todo: perform logging, in default action
				}
				
				switch ($action) {
				case 1:
					//show 404 / 403
					break;
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
		if (!isset($_COOKIE[self::$cookieName])) {
			self::createCookie();
		} else {
			//reset the cookie to a longer period
			setcookie(self::$cookieName, 
				$_COOKIE[self::$cookieName], 
				time() + self::$cookieExpiryTime);
		}
	}

	/**
	 * function to set auth cookie 
	 * @param: void
	 */
	public static function createCookie()
	{
		setcookie(self::$cookieName, 
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

	    
	    if (!file_exists(CSRFP_SELF .CSRFP_JS)) {
	        //die("CSRFGuard js file not found!");
	    }

	    $script = "
	    <script type='text/javascript'>
	        var csrfProtectorToken = '" .self::$cookieName ."';\n</script>" .PHP_EOL;
	    $script .= '<script type="text/javascript" src="' .CSRFP_SELF .CSRFP_JS .'"></script>';	

	    //implant the CSRFGuard js file to outgoing script
	    $buffer = str_ireplace('</body>', $script . '</body>', $buffer, $count);
	    if (!$count) {
	        $buffer .= $script;
	    }

	    return $buffer;
	}
};

