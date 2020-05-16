/** 
 * =================================================================
 * Javascript code for OWASP CSRF Protector
 * Task it does: Fetch csrftoken from cookie, and attach it to every
 * 		POST request
 *		Allowed GET url
 *			-- XHR
 *			-- Static Forms
 *			-- URLS (GET only)
 *			-- dynamic forms
 * =================================================================
 */

var CSRFP_FIELD_TOKEN_NAME = 'csrfp_hidden_data_token';
var CSRFP_FIELD_URLS = 'csrfp_hidden_data_urls';

var CSRFP = {
	CSRFP_TOKEN: 'CSRFP-Token',
	/**
	 * Array of pattern of urls, for which CSRF token needs to be added for GET
     * request.
     * 
     * This is provided from server
	 *
	 * @var {Array}
	 */
	checkForUrls: [],
    /**
	 * Checks if the url doesn't need protection from CSRF.
     * 
	 * @param {String} url - URL to check
	 * @return {Boolean} true if CSRF protection is not needed
	 */
	_isValidGetRequest: function(url) {
		for (var i = 0; i < CSRFP.checkForUrls.length; i++) {
			var match = CSRFP.checkForUrls[i].exec(url);
			if (match !== null && match.length > 0) {
				return false;
			}
		}
		return true;
    },
	/**
	 * Returns CSRF Auth token.
	 *
	 * @return {String} CSRF Token from cookie.
	 */
	_getAuthKey: function() {
        var pattern = "([^;]+)(;|$)";
		var regex = new RegExp(`${CSRFP.CSRFP_TOKEN}=${pattern}`);
		var regexResult = regex.exec(document.cookie);
		if (!regexResult) {
			return null;
        }

		return regexResult[1];
	},
	/** 
	 * Returns domain name from url
	 *
	 * @param {String} url - any url
	 * @return {String} domain name of url
	 */
	_getDomain: function(url) {
		if (url.indexOf("http://") !== 0 && url.indexOf("https://") !== 0) {
            var urlParts = url.split("/");
            if (urlParts && urlParts.length > 0) {
                return urlParts[0];
            }

            return null;
        }

		return /http(s)?:\/\/([^\/]+)/.exec(url)[2];
	},
	/**
	 * Create and return hidden input element with CSRF token.
	 *
	 * @return {HTMLInputElement} input element
	 */
	_createInputElement: function() {
		var htmlElement = document.createElement("input");
		htmlElement.setAttribute('name', CSRFP.CSRFP_TOKEN);
		htmlElement.setAttribute('class', CSRFP.CSRFP_TOKEN);
		htmlElement.type = 'hidden';
		htmlElement.value = CSRFP._getAuthKey();
		return htmlElement;
	},
	/**
	 * Returns absolute path from base and relative path of url.
	 *
	 * @param {String} base base url
	 * @param {String} relative relative url
	 *
	 * @return {String} absolute path
	 */
	_getAbsolutePath: function(base, relative) {
		var stack = base.split("/");
		var parts = relative.split("/");
		// remove current file name (or empty string)
		// (omit if "base" is the current folder without trailing slash)
		stack.pop(); 
			 
		for (var i = 0; i < parts.length; i++) {
			if (parts[i] === ".") {
				continue;
            }

			if (parts[i] === "..") {
				stack.pop();
            } else {
				stack.push(parts[i]);
            }
        }

		return stack.join("/");
	},
	/**
	 * Remove jcsrfp-token run fun and then put them back
	 *
	 * @param {Function} originalFunction - function to wrap
	 * @param {Object} obj reference form obj
	 *
	 * @return wrapped function
	 */
	_csrfpWrap: function(originalFunction, obj) {
		return function(event) {
			// Remove CSRf token if exists
			if (typeof obj[CSRFP.CSRFP_TOKEN] !== 'undefined') {
				var target = obj[CSRFP.CSRFP_TOKEN];
				target.parentNode.removeChild(target);
			}
			
			// Trigger the functions
			var result = originalFunction.apply(this, [event]);
			
			// Now append the CSRFP-Token back
			obj.appendChild(CSRFP._createInputElement());
			
			return result;
		};
	},
	/**
	 * Initialises the CSRFProtector js script
	 *
	 * @param: void
	 *
	 * @return void
	 */
	_init: function() {
		CSRFP.CSRFP_TOKEN = document.getElementById(CSRFP_FIELD_TOKEN_NAME).value;
		try {
			CSRFP.checkForUrls = JSON.parse(document.getElementById(CSRFP_FIELD_URLS).value);
		} catch (err) {
			console.error(err);
			console.error('[ERROR] [CSRF Protector] unable to parse blacklisted url fields.');
		}

		//convert these rules received from php lib to regex objects
		for (var i = 0; i < CSRFP.checkForUrls.length; i++) {
			CSRFP.checkForUrls[i] = CSRFP.checkForUrls[i].replace(/\*/g, '(.*)')
								.replace(/\//g, "\\/");
			CSRFP.checkForUrls[i] = new RegExp(CSRFP.checkForUrls[i]);
		}
	
	}
	
}; 

//==========================================================
// Adding tokens, wrappers on window onload
//==========================================================

function csrfprotector_init() {
	
	// Call the init function
	CSRFP._init();

	// definition of basic FORM submit event handler to intercept the form request
	// and attach a CSRFP TOKEN if it's not already available
	var BasicSubmitInterceptor = function(event) {
		if (typeof event.target[CSRFP.CSRFP_TOKEN] === 'undefined') {
			event.target.appendChild(CSRFP._createInputElement());
		} else {
			//modify token to latest value
			event.target[CSRFP.CSRFP_TOKEN].value = CSRFP._getAuthKey();
		}
	};

	//==================================================================
	// Adding csrftoken to request resulting from <form> submissions
	// Add for each POST, while for mentioned GET request
	// TODO - check for method
	//==================================================================
	// run time binding
	document.querySelector('body').addEventListener('submit', function(event) {
		if (event.target.tagName.toLowerCase() === 'form') {
			BasicSubmitInterceptor(event);
		}
	});

	// initial binding
	// for(var i = 0; i < document.forms.length; i++) {
	// 	document.forms[i].addEventListener("submit", BasicSubmitInterceptor);
	// }

	//==================================================================
	// Adding csrftoken to request resulting from direct form.submit() call
	// Add for each POST, while for mentioned GET request
	// TODO - check for form method
	//==================================================================
	HTMLFormElement.prototype.submit_ = HTMLFormElement.prototype.submit;
	HTMLFormElement.prototype.submit = function() {
		// check if the FORM already contains the token element
		if (!this.getElementsByClassName(CSRFP.CSRFP_TOKEN).length)
			this.appendChild(CSRFP._createInputElement());
		this.submit_();
	};


	/**
	 * Add wrapper for HTMLFormElements addEventListener so that any further 
	 * addEventListens won't have trouble with CSRF token
	 * todo - check for method
	 */
	HTMLFormElement.prototype.addEventListener_ = HTMLFormElement.prototype.addEventListener;
	HTMLFormElement.prototype.addEventListener = function(eventType, fun, bubble) {
		if (eventType === 'submit') {
			var wrapped = CSRFP._csrfpWrap(fun, this);
			this.addEventListener_(eventType, wrapped, bubble);
		} else {
			this.addEventListener_(eventType, fun, bubble);
		}	
	};

	/**
	 * Add wrapper for IE's attachEvent
	 * todo - check for method
	 * todo - typeof is now obsolete for IE 11, use some other method.
	 */
	if (typeof HTMLFormElement.prototype.attachEvent !== 'undefined') {
		HTMLFormElement.prototype.attachEvent_ = HTMLFormElement.prototype.attachEvent;
		HTMLFormElement.prototype.attachEvent = function(eventType, fun) {
			if (eventType === 'onsubmit') {
				var wrapped = CSRFP._csrfpWrap(fun, this);
				this.attachEvent_(eventType, wrapped);
			} else {
				this.attachEvent_(eventType, fun);
			}
		}
	}


	//==================================================================
	// Wrapper for XMLHttpRequest & ActiveXObject (for IE 6 & below)
	// Set X-No-CSRF to true before sending if request method is 
	//==================================================================

	/** 
	 * Wrapper to XHR open method
	 * Add a property method to XMLHttpRequest class
	 * @param: all parameters to XHR open method
	 * @return: object returned by default, XHR open method
	 */
	function new_open(method, url, async, username, password) {
		this.method = method;
		var isAbsolute = (url.indexOf("./") === -1);
		if (!isAbsolute) {
			var base = location.protocol +'//' +location.host 
							+ location.pathname;
			url = CSRFP._getAbsolutePath(base, url);
		}
		if (method.toLowerCase() === 'get' 
			&& !CSRFP._isValidGetRequest(url)) {
			//modify the url
			if (url.indexOf('?') === -1) {
				url += "?" +CSRFP.CSRFP_TOKEN +"=" +CSRFP._getAuthKey();
			} else {
				url += "&" +CSRFP.CSRFP_TOKEN +"=" +CSRFP._getAuthKey();
			}
		}

		return this.old_open(method, url, async, username, password);
	}

	/** 
	 * Wrapper to XHR send method
	 * Add query parameter to XHR object
	 *
	 * @param: all parameters to XHR send method
	 *
	 * @return: object returned by default, XHR send method
	 */
	function new_send(data) {
		if (this.method.toLowerCase() === 'post') {
			// attach the token in request header
			this.setRequestHeader(CSRFP.CSRFP_TOKEN, CSRFP._getAuthKey());
		}
		return this.old_send(data);
	}

	if (window.XMLHttpRequest) {
		// Wrapping
		XMLHttpRequest.prototype.old_send = XMLHttpRequest.prototype.send;
		XMLHttpRequest.prototype.old_open = XMLHttpRequest.prototype.open;
		XMLHttpRequest.prototype.open = new_open;
		XMLHttpRequest.prototype.send = new_send;
	}
	if (typeof ActiveXObject !== 'undefined') {
		ActiveXObject.prototype.old_send = ActiveXObject.prototype.send;
		ActiveXObject.prototype.old_open = ActiveXObject.prototype.open;
		ActiveXObject.prototype.open = new_open;
		ActiveXObject.prototype.send = new_send;	
	}
	//==================================================================
	// Rewrite existing urls ( Attach CSRF token )
	// Rules:
	// Rewrite those urls which matches the regex sent by Server
	// Ignore cross origin urls & internal links (one with hashtags)
	// Append the token to those url already containing GET query parameter(s)
	// Add the token to those which does not contain GET query parameter(s)
	//==================================================================

	for (var i = 0; i < document.links.length; i++) {
		document.links[i].addEventListener("mousedown", function(event) {
			var href = event.target.href;
			if(typeof href === "string")
			{
				var urlParts = href.split('#');
				var url = urlParts[0];
				var hash = urlParts[1];

				if(CSRFP._getDomain(url).indexOf(document.domain) === -1
					|| CSRFP._isValidGetRequest(url)) {
					//cross origin or not to be protected by rules -- ignore
					return;
				}

				if (url.indexOf('?') !== -1) {
					if(url.indexOf(CSRFP.CSRFP_TOKEN) === -1) {
						url += "&" +CSRFP.CSRFP_TOKEN +"=" +CSRFP._getAuthKey();
					} else {
						url = url.replace(new RegExp(CSRFP.CSRFP_TOKEN +"=.*?(&|$)", 'g'),
							CSRFP.CSRFP_TOKEN +"=" +CSRFP._getAuthKey() + "$1");
					}
				} else {
					url += "?" +CSRFP.CSRFP_TOKEN +"=" +CSRFP._getAuthKey();
				}

				event.target.href = url;
				if (typeof hash !== 'undefined') {
					event.target.href += '#' +hash;
				}
			}
		});
	}

}

window.addEventListener("DOMContentLoaded", function() {
	csrfprotector_init();

	// Dispatch an event so clients know the library has initialized
	var postCsrfProtectorInit = new Event('postCsrfProtectorInit');
	window.dispatchEvent(postCsrfProtectorInit);
}, false);
