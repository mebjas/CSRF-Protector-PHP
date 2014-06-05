/** 
 * =================================================================
 * Javascript code for OWASP CSRF Protector
 * Task: Fetch csrftoken from cookie, and attach it to every
 * 		POST request
 *		Allowed GET url
 * =================================================================
 */

// Array of patterns of url, for which csrftoken need to be added
// In case of GET request also, provided from server
var checkForUrls = new Array(<?php
	if (isset($_GET['param'])) {
		$patternArray = json_decode($_GET['param'],false);
		if ($patternArray) {
			foreach ($patternArray as $key => $value) {
				if ($key !== 0) {
					echo ',';
				}
				echo "'". $value ."'";
			}
		}
	}
?>);

//convert these rules to regex objects
for (var i = 0; i < checkForUrls.length; i++) {
	checkForUrls[i] = checkForUrls[i].replace(/\*/g, '(.*)')
						.replace(/\//g, "\\/");
	checkForUrls[i] = new RegExp(checkForUrls[i]);
}

/**
 * Function to check if a certain url is allowed to perform the request
 * With or without csrf token
 * @param: string, url
 * @return: boolean, 	true if csrftoken is not needed
 * 						false if csrftoken is needed
 */
function isValidGetRequest(url) {
	for (var i = 0; i < checkForUrls.length; i++) {
		var match = checkForUrls[i].exec(url);
		if (match !== null && match.length > 0) {
			return false;
		}
	}
	return true;
}

/** 
 * function to get Auth key from cookie Andreturn it to requesting function
 * @param: void
 * @return: string, csrftoken retrieved from cookie
 */
function getAuthKey() {
	var re = new RegExp("CSRF_AUTH_TOKEN=([^;]+)(;|$)");
	var RegExpArray = re.exec(document.cookie);
	
	if (RegExpArray === null) {
		//#todo: Action to take if CSRFtoken not found
		return false;
	}
	return RegExpArray[1];
}

/** 
 * Function to get domain of any url
 * @param: string, url
 * @return: string, domain of url
 */
function getDomain(url) {
	if (url.indexOf("http://") !== 0 && url.indexOf("https://") !== 0)
		return document.domain;
	return /http(s)?:\/\/([^\/]+)/.exec(url)[2];
}

//==========================================================
// Adding tokens, wrappers on window onload
//==========================================================

window.onload = function() {

	//==================================================================
	// Adding csrftoken to request resulting from <form> submissions
	// Add for each POST, while for mentioned GET request
	//==================================================================
	for(var i = 0; i < document.forms.length; i++) {
		document.forms[i].onsubmit = function(event) {
			if (!event.target.csrfp_token) {
				var hiddenObj = document.createElement("input");
				hiddenObj.name = 'csrfp_token';
				hiddenObj.type = 'hidden';
				hiddenObj.value = getAuthKey();
				event.target.appendChild(hiddenObj);
			}
		};
	}


	//==================================================================
	// Wrapper for XMLHttpRequest
	// Set X-No-CSRF to true before sending if request method is 
	//==================================================================

	/** 
	 * Wrapper to XHR open method
	 * Add a property method to XMLHttpRequst class
	 * @param: all parameters to XHR open method
	 * @return: object returned by default, XHR open method
	 */
	function new_open(method, url, async, username, password) {
		this.method = method;

		if (method.toLowerCase() === 'get' && !isValidGetRequest(url)) {
			//modify the url
			if (url.indexOf('?') === -1) {
				url += "?csrfp_token=" +getAuthKey();
			} else {
				url += "&csrfp_token" +getAuthKey();
			}
		}

		return this.old_open(method, url, async, username, password);
	}

	/** 
	 * Wrapper to XHR send method
	 * Add query paramter to XHR object
	 * @param: all parameters to XHR send method
	 * @return: object returned by default, XHR send method
	 */
	function new_send(data) {
		if (this.method.toLowerCase() === 'post') {
			
			//#needDiscussion: whats the utility, was used in paper by Riccardo
			this.setRequestHeader("X-No-CSRF", "true");
			
			if (data !== undefined) {
				data += "&";
			} else {
				data = "";
			}
			
			data += "csrfp_token=" +getAuthKey();
		}
		return this.old_send(data);
	}

	//wrappig
	XMLHttpRequest.prototype.old_send = XMLHttpRequest.prototype.send;
	XMLHttpRequest.prototype.old_open = XMLHttpRequest.prototype.open;
	XMLHttpRequest.prototype.open = new_open;
	XMLHttpRequest.prototype.send = new_send;

	//==================================================================
	// Rewrite existing urls ( Attach CSRF token )
	// Rules:
	// Rewrite those urls which matches the regex sent by Server
	// Ingore cross origin urls & internal links (one with hashtags)
	// Append the token to those url already containig GET query parameter(s)
	// Add the token to those which does not contain GET query parameter(s)
	//==================================================================

	for (var i = 0; i < document.links.length; i++) {

		var urlDisect = document.links[i].href.split('#');
		var url = urlDisect[0];
		var hash = urlDisect[1];
		
		if(getDomain(url).indexOf(document.domain) === -1) {
			//cross origin -- ignore
			continue;
		}
		if (isValidGetRequest(url)) {
			//not provided in rules
			continue;
		}
		
		if (url.indexOf('?') !== -1) {
			url += "&csrfp_token=" +getAuthKey();
		} else {
			url += "?csrfp_token=" +getAuthKey();
		}
		
		document.links[i].href = url;
		if (hash !== undefined) {
			document.links[i].href += '#' +hash;
		}
	}

}