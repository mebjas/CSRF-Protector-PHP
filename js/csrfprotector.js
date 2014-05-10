/** 
 * javascript code for OWASP CSRF Protector
 */


for(var i = 0; i<document.forms.length; i++) {
	document.forms[i].onsubmit = function(evt) {
		if (!evt.srcElement.CSRFPROTECTOR_AUTH_TOKEN) {
			evt.srcElement.innerHTML += "<input type='hidden' name='CSRFPROTECTOR_AUTH_TOKEN' value='" 
			+getAuthKey() +"'>";
		}
	};
}


/** 
 * function to get Auth key from cookie and return it to requesting function
 */
function getAuthKey() {
	var re = new RegExp("CSRF_AUTH_TOKEN=([^;]+)(;|$)");
	if(authKey === null) {
		var RegExpArray = re.exec(document.cookie);
		return RegExpArray[1];
	}
	return authKey;
}

/** 
 * function to get domain of any url
 */
function getDomain(url) {
	// proxy doesn't work on https anyway
	if (url.indexOf("http://") !== 0)
		return document.domain;
	return /http:\/\/([^\/]+)/.exec(url)[1];
}


//===============================================================
// Writing wrapper for XMLHttpRequest
// Set X-No-CSRF to true before sending if request method is POST
//===============================================================

//add a property method to XMLHttpRequst class
function new_open(method, url, async, username, password) {
	this.method = method;
	return this.old_open(method, url, async, username, password);
}

//currently functional for POST requests only
function new_send(data) {
	if (this.method === "POST") {
		this.setRequestHeader("X-No-CSRF", "true");
		if(data.length !== 0)
   		data += "&";
    	data += "CSRFPROTECTOR_AUTH_TOKEN=" +getAuthKey();
    }
    return this.old_send(data);
}


XMLHttpRequest.prototype.old_send = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.old_open = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = new_open;
XMLHttpRequest.prototype.send = new_send;

//================================================================
// Rewrite existing urls for CSRF token
// Rules:
// Ingore cross origin urls & internal links (one with hashtags)
// Append the token to those url already containig GET query parameter(s)
// Add the token to those which does not contain GET query parameter(s)
//================================================================
for (var i = 0; i<document.links.length; i++) {
	if(getDomain(document.links[i].href).indexOf(document.domain) === -1) {
		//cross origin -- ignore
		continue;
	} else if (document.links[i].href.indexOf('#') !== -1) {
		//hash tag | internal link -- ignore
		continue;
	} else if (document.links[i].href.indexOf('?') !== -1) {
		document.links[i].href += "&CSRFPROTECTOR_AUTH_TOKEN=" +getAuthKey();
	} else {
		if (document.links[i].href[document.links[i].href.length - 1] != '/') {
			document.links[i].href += '/';
		}
		document.links[i].href += "?CSRFPROTECTOR_AUTH_TOKEN=" +getAuthKey();
	}
}