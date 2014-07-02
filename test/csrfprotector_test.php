<?php

require __DIR__ .'/../libs/csrf/csrfprotector.php';

class csrfp_test extends PHPUnit_Framework_TestCase
{
    /**
     * Function to be run before every test*() functions.
     */
    public function setUp()
    {

    }

    /**
     * Function to check refreshToken() functionality
     */
    public function testRefreshToken()
    {
        /*
        $val = $_SESSION[CSRFP_TOKEN] = $_COOKIE[CSRFP_TOKEN] = '123abcd';

        
        csrfProtector::$config['tokenLength'] = 20;
        //csrfProtector::refreshToken();

        $this->assertTrue(strcmp($val, $_SESSION[CSRFP_TOKEN]) != 0);
        $this->assertTrue(strcmp($val, $_COOKIE[CSRFP_TOKEN]) != 0);
        */

        $this->markTestSkipped('This sets cookie header, causing error - headers already sent');
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
        csrfprotector::$config['jsPath'] = '../js/csrfprotector.js';
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

        $_SERVER['REQUEST_SCHEME'] = 'http';
        $_SERVER['HTTP_HOST'] = 'test';

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