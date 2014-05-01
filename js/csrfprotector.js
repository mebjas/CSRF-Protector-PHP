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