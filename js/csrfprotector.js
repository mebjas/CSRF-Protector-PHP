var authKey = null;

for(var i = 0; i<document.forms.length; i++) {
	document.forms[i].onsubmit = function(evt) {
		if (!evt.srcElement.CSRFPROTECTOR_AUTH_TOKEN) {
			evt.srcElement.innerHTML += "<input type='hidden' name='CSRFPROTECTOR_AUTH_TOKEN' value='" 
			+getAuthKey() +"'>";
		}
	};
}

function getAuthKey() {
	var re = new RegExp("CSRF_AUTH_TOKEN=([^;]+)(;|$)");
	if(authKey === null) {
		var RegExpArray = re.exec(document.cookie);
		return RegExpArray[1];
	}
	return authKey;
}


function getDomain(url) {
	// proxy doesn't work on https anyway
	if (url.indexOf("http://") !== 0)
		return document.domain;
	return /http:\/\/([^\/]+)/.exec(url)[1];
}

function new_open(method, url, async, username, password) {
	return this.old_open(method, url, async, username, password);
}
function new_send(data) {
   if (this.method === "POST") {
      this.setRequestHeader("X-No-Csrf", "true");
   }
   data += "&CSRFPROTECTOR_AUTH_TOKEN=" +getAuthKey();
   this.old_send(data);
}


XMLHttpRequest.prototype.old_send = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.old_open = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = new_open;
XMLHttpRequest.prototype.send = new_send;