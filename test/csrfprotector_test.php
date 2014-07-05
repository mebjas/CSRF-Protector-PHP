<?php

require_once __DIR__ .'/../libs/csrf/csrfprotector.php';

/**
 * Wrapper class for testing purpose
 */
class csrfp_wrapper extends csrfprotector
{
    /**
     * Function to provide wrapper methode to set the protected var, requestType
     */
    public static function changeRequestType($type)
    {
        self::$requestType = $type;
    }

    public static function checkHeader($needle)
    {
        $haystack = xdebug_get_headers();
        foreach ($haystack as $key => $value) {
            if (strpos($value, $needle) !== false)
                return true;
        }
        return false;
    }
}


/**
 * main test class
 */
class csrfp_test extends PHPUnit_Framework_TestCase
{
    /**
     * Function to be run before every test*() functions.
     */
    public function setUp()
    {
        csrfprotector::$config['jsPath'] = '../js/csrfprotector.js';
        $_SERVER['REQUEST_URI'] = 'temp';       // For logging
        $_SERVER['REQUEST_SCHEME'] = 'http';    // For authorisePost
        $_SERVER['HTTP_HOST'] = 'test';         // For isUrlAllowed
        $_SERVER['PHP_SELF'] = '/index.php';     // For authorisePost

        csrfprotector::$config['verifyGetFor'] = array('http://test/index*');    // For authorisePost
        $_POST[CSRFP_TOKEN] = $_GET[CSRFP_TOKEN] = '123';
        $_SESSION[CSRFP_TOKEN] = 'abc'; //token mismatch - leading to failed validation
        $_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
    }

    /**
     * Function to check refreshToken() functionality
     */
    public function testRefreshToken()
    {
        
        $val = $_SESSION[CSRFP_TOKEN] = $_COOKIE[CSRFP_TOKEN] = '123abcd';

        
        csrfProtector::$config['tokenLength'] = 20;
        csrfProtector::refreshToken();

        $this->assertTrue(strcmp($val, $_SESSION[CSRFP_TOKEN]) != 0);

        $this->assertTrue(csrfP_wrapper::checkHeader('Set-Cookie'));
        $this->assertTrue(csrfP_wrapper::checkHeader('csrfp_token'));
    }

    /**
     * test useCachedVersion()
     */
    public function testUseCachedVersion()
    {
        if (filemtime(__DIR__ .'/../js/csrfprotector.js') < filemtime(__DIR__ .'/../libs/config.php')) {
            $this->assertFalse(csrfprotector::useCachedVersion());
        } else {
            $this->assertTrue(csrfprotector::useCachedVersion());
        }

        $temp = csrfprotector::$config['jsPath'];
        csrfprotector::$config['jsPath'] = 'some_random_name';
        $this->assertFalse(csrfprotector::useCachedVersion());
        csrfprotector::$config['jsPath'] = $temp;
    }

    public function testCreateNewJsCache()
    {
        $this->markTestSkipped('todo, some method to test this function');
    }

    /**
     * test authorise post -> log directory exception
     */
    public function testAuthorisePost_logdirException()
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        csrfprotector::$config['logDirectory'] = 'unknown_location';

        try {
            csrfprotector::authorisePost();
        } catch (logDirectoryNotFoundException $ex) {
            return;;
        }
        $this->fail('logDirectoryNotFoundException has not been raised.');
    }

    /**
     * test authorise post -> action = 403, forbidden
     */
    public function testAuthorisePost_failedAction_1()
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        
        csrfprotector::$config['logDirectory'] = '../log';
        csrfprotector::$config['failedAuthAction']['POST'] = 0;
        csrfprotector::$config['failedAuthAction']['GET'] = 0;

        //csrfprotector::authorisePost();
        $this->markTestSkipped('Cannot add tests as code exit here');

        $_SERVER['REQUEST_METHOD'] = 'GET';
        csrfp_wrapper::changeRequestType('GET');
        //csrfprotector::authorisePost();

        $this->markTestSkipped('Cannot add tests as code exit here');
    }

    /**
     * test authorise post -> strip $_GET, $_POST
     */
    public function testAuthorisePost_failedAction_2()
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';

        csrfprotector::$config['logDirectory'] = '../log';
        csrfprotector::$config['failedAuthAction']['POST'] = 1;
        csrfprotector::$config['failedAuthAction']['GET'] = 1;

        $_POST = array('param1' => 1, 'param2' => 2);
        csrfprotector::authorisePost();
        $this->assertEmpty($_POST);

        $_SERVER['REQUEST_METHOD'] = 'GET';
        csrfp_wrapper::changeRequestType('GET');
        $_GET = array('param1' => 1, 'param2' => 2);

        csrfprotector::authorisePost();
        $this->assertEmpty($_GET);
    }

    /**
     * test authorise post -> redirect
     */
    public function testAuthorisePost_failedAction_3()
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';

        csrfprotector::$config['logDirectory'] = '../log';
        csrfprotector::$config['errorRedirectionPage'] = 'http://test';
        csrfprotector::$config['failedAuthAction']['POST'] = 2;
        csrfprotector::$config['failedAuthAction']['GET'] = 2;

        //csrfprotector::authorisePost();
        $this->markTestSkipped('Cannot add tests as code exit here');

        $_SERVER['REQUEST_METHOD'] = 'GET';
        csrfp_wrapper::changeRequestType('GET');
        //csrfprotector::authorisePost();
        $this->markTestSkipped('Cannot add tests as code exit here');
    }

    /**
     * test authorise post -> error message & exit
     */
    public function testAuthorisePost_failedAction_4()
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';

        csrfprotector::$config['logDirectory'] = '../log';
        csrfprotector::$config['customErrorMessage'] = 'custom error message';
        csrfprotector::$config['failedAuthAction']['POST'] = 3;
        csrfprotector::$config['failedAuthAction']['POST'] = 3;

        //csrfprotector::authorisePost();
        $this->markTestSkipped('Cannot add tests as code exit here');

        $_SERVER['REQUEST_METHOD'] = 'GET';
        csrfp_wrapper::changeRequestType('GET');
        //csrfprotector::authorisePost();
        $this->markTestSkipped('Cannot add tests as code exit here');
    }

    /**
     * test authorise post -> 500 internal server error
     */
    public function testAuthorisePost_failedAction_5()
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';

        csrfprotector::$config['logDirectory'] = '../log';
        csrfprotector::$config['failedAuthAction']['POST'] = 4;
        csrfprotector::$config['failedAuthAction']['GET'] = 4;

        //csrfprotector::authorisePost();
        //$this->markTestSkipped('Cannot add tests as code exit here');

        $_SERVER['REQUEST_METHOD'] = 'GET';
        csrfp_wrapper::changeRequestType('GET');
        //csrfprotector::authorisePost();
        //csrfp_wrapper::checkHeader('500');
        //$this->markTestSkipped('Cannot add tests as code exit here');
    }

    /**
     * test authorise post -> default action: strip $_GET, $_POST
     */
    public function testAuthorisePost_failedAction_6()
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';

        csrfprotector::$config['logDirectory'] = '../log';
        csrfprotector::$config['failedAuthAction']['POST'] = 10;
        csrfprotector::$config['failedAuthAction']['GET'] = 10;

        $_POST = array('param1' => 1, 'param2' => 2);
        csrfprotector::authorisePost();
        $this->assertEmpty($_POST);

        $_SERVER['REQUEST_METHOD'] = 'GET';
        csrfp_wrapper::changeRequestType('GET');
        $_GET = array('param1' => 1, 'param2' => 2);

        csrfprotector::authorisePost();
        $this->assertEmpty($_GET);
    }
    /**
     * test for generateAuthToken()
     */
    public function testGenerateAuthToken()
    {
        csrfprotector::$config['tokenLength'] = 20;
        $token1 = csrfprotector::generateAuthToken();
        $token2 = csrfprotector::generateAuthToken();

        $this->assertFalse($token1 == $token2);
        $this->assertEquals(strlen($token1), 20);
    }

    /**
     * test ob_handler_function
     */
    public function testob_handler()
    {
        csrfprotector::$config['disabledJavascriptMessage'] = 'test message';
        csrfprotector::$config['jsUrl'] = 'http://localhost/test/csrf/js/csrfprotector.js';

        $testHTML = '<html>';
        $testHTML .= '<head><title>1</title>';
        $testHTML .= '<body onload="test()">';
        $testHTML .= '-- some static content --';
        $testHTML .= '-- some static content --';
        $testHTML .= '</body>';
        $testHTML .= '</head></html>';

        $modifiedHTML = csrfprotector::ob_handler($testHTML, 0);

        $inpLength = strlen($testHTML);
        $outLength = strlen($modifiedHTML);

        //Check if file has been modified
        $this->assertFalse($outLength == $inpLength);

        // Check if content after <body..> is <noscript #todo
        $this->markTestSkipped('todo, add appropriate test here');
        // Check if content before </body> is </script> #todo
        $this->markTestSkipped('todo, add appropriate test here');
    }

    /**
     * testing exception in logging function
     */
    public function testLoggingException()
    {
        $this->markTestSkipped('Should not test private methods');
    }

    /**
     * Tests isUrlAllowed() function for various urls and configuration
     */
    public function testisURLallowed()
    {
        csrfprotector::$config['verifyGetFor'] = array('http://test/delete*', 'https://test/*');

        $_SERVER['PHP_SELF'] = '/nodelete.php';
        $this->assertTrue(csrfprotector::isURLallowed());

        $_SERVER['PHP_SELF'] = '/index.php';
        $this->assertTrue(csrfprotector::isURLallowed('http://test/index.php'));

        $_SERVER['PHP_SELF'] = '/delete.php';
        $this->assertFalse(csrfprotector::isURLallowed('http://test/delete.php'));

        $_SERVER['PHP_SELF'] = '/delete_user.php';
        $this->assertFalse(csrfprotector::isURLallowed('http://test/delete_users.php'));

        $_SERVER['REQUEST_SCHEME'] = 'https';
        $_SERVER['PHP_SELF'] = '/index.php';
        $this->assertFalse(csrfprotector::isURLallowed('https://test/index.php'));

        $_SERVER['PHP_SELF'] = '/delete_user.php';
        $this->assertFalse(csrfprotector::isURLallowed('https://test/delete_users.php'));
    }

    /**
     * Test for exception thrown when env variable is set by mod_csrfprotector
     */
    public function testModCSRFPEnabledException()
    {
        putenv('mod_csrfp_enabled=true');
        try {
            csrfProtector::init();            
        } catch (modCSRFProtectorEnabledException $ex) {
            return;
        }
        $this->fail('modCSRFProtectorEnabledException has not been raised.');
    }
}