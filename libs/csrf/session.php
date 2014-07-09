<?php

define("CSRFPSESSID", "CSRFPSESSID");

class Session
{
    protected static $expiryTimeout = 30 * 60;	// 30 Minutes
    protected $sessionID;
    protected $csrfToken;
    protected static $config = null;
    protected $dbConnection;

    function __construct()
    {
        $this->dbConnection = new PDO('mysql:dbname=' .self::$config['dbname'] 
        		.';host=' .self::$config['host'] .';charset=utf8', self::$config['user'],
        		self::$config['password']);

		$this->dbConnection->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
		$this->dbConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        if (isset($_COOKIE[CSRFPSESSID])) {
        	// Session ID set - existing session
        	$this->sessionID = $_COOKIE[CSRFPSESSID];

        	

			$stmt = $dbConnection->prepare('SELECT `value` FROM CSRFPSESSION WHERE `sessid` = ?');
			$stmt->bind_param('s', $this->sessionID);

			$stmt->execute();

			$result = $stmt->get_result();
			$row = $result->fetch_assoc();

			if (count($row) > 0) {
				$this->csrfToken = $row['value'];
			} else {
				//expired or invalid session -- generate new one
				$this->newSession();
			}
        } else {
        	$this->newSession();
        }
    }

    private function newSession()
    {
    	$this->csrfToken = '';
    	while (true) {
    		$sessionID = self::generateAuthToken(20);

    	}
    }

    private function refreshToken()
    {
    	setcookie(CSRFPSESSID, $this->sessionID, time() +self::$expiryTimeout);
    }

    private function SQL($query, $array)
    {

    }
    
    /**
	 * function to generate random hash of length as given in parameter
	 * max length = 128
	 * @param: length to hash required, int
	 * @return string
	 */
	public static function generateAuthToken($length)
	{
		//if $length > 128 throw exception #todo 
		$length = intval($length);

		if (function_exists("hash_algos") && in_array("sha512", hash_algos())) {
			$token = hash("sha512", mt_rand(0, mt_getrandmax()));
		} else {
			$token = '';
			for ($i = 0; $i < $length; ++$i) {
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
}

?>
