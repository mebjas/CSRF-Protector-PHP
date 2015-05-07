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
     * @var to hold current configurations
     */
    protected $config = array();

    /**
     * Function to be run before every test*() functions.
     */
    public function setUp()
    {
        $this->config = include(__DIR__ .'/../libs/config.sample.php');

        csrfprotector::$config['jsPath'] = '../js/csrfprotector.js';
        csrfprotector::$config['noJs'] = true;
        csrfprotector::$config['CSRFP_TOKEN'] = 'csrfp_token';

        $_SERVER['REQUEST_URI'] = 'temp';       // For logging
        $_SERVER['REQUEST_SCHEME'] = 'http';    // For authorisePost
        $_SERVER['HTTP_HOST'] = 'test';         // For isUrlAllowed
        $_SERVER['PHP_SELF'] = '/index.php';     // For authorisePost
        $_POST[CSRFP_TOKEN] = $_GET[CSRFP_TOKEN] = '123';
        $_SESSION[CSRFP_TOKEN] = $_COOKIE[CSRFP_TOKEN] = 'abc'; //token mismatch - leading to failed validation
        $_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';

        // Create an instance of config file -- for testing
        $data = file_get_contents(__DIR__ .'/../libs/config.sample.php');
        file_put_contents(__DIR__ .'/../libs/config.php', $data);      
    }

    /**
     * tearDown()
     */
    public function tearDown()
    {
        unlink(__DIR__ .'/../libs/config.php');
    }

    /**
     * Function to check refreshToken() functionality
     */
    public function testRefreshToken()
    {
        
        $val = $_SESSION[CSRFP_TOKEN] = $_COOKIE[CSRFP_TOKEN] = '123abcd';

        
        csrfProtector::$config['tokenLength'] = 20;
        csrfProtector::refreshToken();

        // Token is not refreshed
        $this->assertFalse(strcmp($val, $_SESSION[CSRFP_TOKEN]) != 0);

        $this->assertTrue(csrfP_wrapper::checkHeader('Set-Cookie'));
        $this->assertTrue(csrfP_wrapper::checkHeader('csrfp_token'));
        $this->assertTrue(csrfp_wrapper::checkHeader($_SESSION[CSRFP_TOKEN]));
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
            $this->assertTrue(true);
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
        csrfprotector::$config['verifyGetFor'] = array('http://test/index*');
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
        csrfprotector::$config['verifyGetFor'] = array('http://test/index*');
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
        csrfprotector::$config['verifyGetFor'] = array('http://test/index*');
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
        csrfprotector::$config['verifyGetFor'] = array('http://test/index*');
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
        csrfprotector::$config['verifyGetFor'] = array('http://test/index*');
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
        csrfprotector::$config['verifyGetFor'] = array('http://test/index*');
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
     * test authorise success
     */
    public function testAuthorisePost_success()
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST[CSRFP_TOKEN] = $_GET[CSRFP_TOKEN] = $_SESSION[CSRFP_TOKEN];
        $temp = $_SESSION[CSRFP_TOKEN];

        csrfprotector::authorisePost(); //will create new session and cookies

        // Token doesn't changes
        $this->assertTrue($temp == $_SESSION[CSRFP_TOKEN]);
        $this->assertTrue(csrfp_wrapper::checkHeader('Set-Cookie'));
        $this->assertTrue(csrfp_wrapper::checkHeader('csrfp_token'));
        $this->assertTrue(csrfp_wrapper::checkHeader($_SESSION[CSRFP_TOKEN]));  // Combine these 3 later

        // For get method
        $_SERVER['REQUEST_METHOD'] = 'GET';
        csrfp_wrapper::changeRequestType('GET');
        $_POST[CSRFP_TOKEN] = $_GET[CSRFP_TOKEN] = $_SESSION[CSRFP_TOKEN];
        $temp = $_SESSION[CSRFP_TOKEN];

        csrfprotector::authorisePost(); //will create new session and cookies

        $this->assertTrue($temp == $_SESSION[CSRFP_TOKEN]);
        $this->assertTrue(csrfp_wrapper::checkHeader('Set-Cookie'));
        $this->assertTrue(csrfp_wrapper::checkHeader('csrfp_token'));
        $this->assertTrue(csrfp_wrapper::checkHeader($_SESSION[CSRFP_TOKEN]));  // Combine these 3 later
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

        csrfprotector::$config['tokenLength'] = 128;
        $token = csrfprotector::generateAuthToken();
        $this->assertEquals(strlen($token), 128);
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
        $this->assertTrue(strpos($modifiedHTML, '<noscript>') !== false);
        $this->assertTrue(strpos($modifiedHTML, '<script') !== false);
    }

    /**
     * test ob_handler_function for output filter
     */
    public function testob_handler_positioning()
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

        $this->assertEquals(strpos($modifiedHTML, '<body') + 23, strpos($modifiedHTML, '<noscript'));
        // Check if content before </body> is </script> #todo
        //$this->markTestSkipped('todo, add appropriate test here');
    }

    /**
     * testing exception in logging function
     */
    public function testLoggingException()
    {
        $this->markTestSkipped('Cannot test private methods');
    }

    /**
     * Test getAbsoluteUrl function
     */
    public function testGetAbsoluteURL()
    {
        $this->assertSame('http://test/index.php', csrfprotector::getAbsoluteURL('http://test/index.php'));
        $this->assertSame('http://test/delete.php', csrfprotector::getAbsoluteURL('./delete.php'));
        $this->assertSame('http://delete.php', csrfprotector::getAbsoluteURL('../delete.php'));
        $this->assertSame('http://test2/delete.php', csrfprotector::getAbsoluteURL('../test2/delete.php'));
        $this->assertSame('http://test/test2/delete.php', csrfprotector::getAbsoluteURL('./test2/delete.php'));        
    }
    
    /**
     * Tests isUrlAllowed() function for various urls and configuration
     */
    public function testisURLallowed()
    {
        csrfprotector::$config['verifyGetFor'] = array('http://test/delete*', 'https://test/*');

        $this->assertTrue(csrfprotector::isURLallowed('http"//test/nodelete.php'));

        $this->assertTrue(csrfprotector::isURLallowed('http://test/index.php'));

        $this->assertFalse(csrfprotector::isURLallowed('http://test/delete.php'));

        $this->assertFalse(csrfprotector::isURLallowed('http://test/delete_users.php'));

        $this->assertFalse(csrfprotector::isURLallowed('https://test/index.php'));

        $this->assertFalse(csrfprotector::isURLallowed('https://test/delete_users.php'));
    }

    /**
     * Test for exception thrown when env variable is set by mod_csrfprotector
     */
    public function testModCSRFPEnabledException()
    {
        putenv('mod_csrfp_enabled=true');
        $temp = $_SESSION[CSRFP_TOKEN] = $_COOKIE[CSRFP_TOKEN] = 'abc';
        csrfProtector::init();

        // Assuming no cookie change
        $this->assertTrue($temp == $_SESSION[CSRFP_TOKEN]);
        $this->assertTrue($temp == $_COOKIE[CSRFP_TOKEN]);
    }

    /**
     * Test for rewriteHTML()
     */
    public function testRewriteHTML()
    {
        $_COOKIE[CSRFP_TOKEN] = 'abc';
        $buffer = "<form action='./test'><input type='text' name='test'></form>";
        $buffer = csrfprotector::rewriteHTML($buffer);
        $this->assertTrue(strpos($buffer, "<input type='hidden' name='" .CSRFP_TOKEN) != false);

        csrfprotector::$config['verifyGetFor'] = array("http://test/delete.php");
        $buffer = "<a href='http://test/delete.php'></a>";
        $buffer_ = csrfprotector::rewriteHTML($buffer);
        $this->assertTrue(strpos($buffer_, "?" .CSRFP_TOKEN ."=" .$_COOKIE[CSRFP_TOKEN]) != false);

        // No modification case
        $buffer = "<a href='http://test/index.php'></a>";
        $buffer_ = csrfprotector::rewriteHTML($buffer);
        $this->assertSame($buffer, $buffer_);

    }

    /**
     * function to test modifyURL()
     */
    public function testModifyURL()
    {
        $token = 'abcxxcd';

        // Url already contains token
        $url = 'http://test/test.php?csrfp_token=' .$token;
        $url_ = csrfprotector::modifyURL($url, $token);
        $this->assertSame($url, $url_);

        // Url without argument
        $url = 'http://test/test.php';
        $url_ = csrfprotector::modifyURL($url, $token);
        $this->assertTrue(strpos($url_, "?" .CSRFP_TOKEN ."=" .$token) != false);

        // Url with argument
        $url = 'http://test/test.php?a=1&b=2';
        $url_ = csrfprotector::modifyURL($url, $token);
        $this->assertTrue(strpos($url_, "&" .CSRFP_TOKEN ."=" .$token) != false);
    }
}