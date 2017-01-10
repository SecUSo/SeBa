var certificationInformation = {

	status: "",
	securityState: "",
	securityDescription: "",
	securityErrorMessage: "",
	commonName: "",
	organization: "",
	issuerOrganization: "",
	sha1Fingerprint: "",
	notBeforeGMT: "",
	notAfterGMT: "",
	issuerCN: "",
	issuerOU: "",
	issuerO: "",
	issuerC: "",
	domainMismatch: "",
	notValid: "",
	untrusted: "", 

	loadInformation: function (xhr, error) {
		certificationInformation.clear();
		let channel = xhr.channel;

		try {
			if (!error) {
				certificationInformation.status = "succeeded";
			}
			else {
				certificationInformation.status = "failed";
			}

			let secInfo = channel.securityInfo;

			if (secInfo instanceof Ci.nsITransportSecurityInfo) {
				secInfo.QueryInterface(Ci.nsITransportSecurityInfo);

				// Check security state flags
				if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE) == Ci.nsIWebProgressListener.STATE_IS_SECURE) {
					certificationInformation.securityState = "secure";
				}
				else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_INSECURE) == Ci.nsIWebProgressListener.STATE_IS_INSECURE) {
					certificationInformation.securityState = "insecure";
				}
				else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_BROKEN) == Ci.nsIWebProgressListener.STATE_IS_BROKEN) {
					certificationInformation.securityState = "unknown";
					certificationInformation.securityDescription = secInfo.shortSecurityDescription;
					certificationInformation.securityErrorMessage = secInfo.errorMessage;
				}
			}

			if (secInfo instanceof Ci.nsISSLStatusProvider) {
				var cert = secInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus.QueryInterface(Ci.nsISSLStatus).serverCert;
				var status = gBrowser.securityUI.QueryInterface(Components.interfaces.nsISSLStatusProvider).SSLStatus;
				
				if (status && !status.isUntrusted) {
					if (status.isExtendedValidation) {
						urlPruning.setHttpsEVInfo(); //Extended validation
					}

					certificationInformation.domainMismatch = status.isDomainMismatch; // Domain of certificate doesn't match website
					certificationInformation.notValid = status.isNotValidAtThisTime; // Expired
					certificationInformation.untrusted = status.isUntrusted; // Missing or untrusted issuer/ self signed

					// Cipher: status.cipherName);
					// Key length: status.keyLength);
					// Protocol: status.protocolVersion); //  0:SSL3, 1: TLS1, 2: TLS1.1, 3: TLS1.2, 4: TLS1.3  
				}
				
				certificationInformation.commonName = cert.commonName;
				certificationInformation.organization = cert.organization;
				certificationInformation.issuerOrganization = cert.issuerOrganization;
				certificationInformation.sha1Fingerprint = cert.sha1Fingerprint;

				var validity = cert.validity.QueryInterface(Ci.nsIX509CertValidity);

				certificationInformation.notBeforeGMT = validity.notBeforeGMT;
				certificationInformation.notAfterGMT = validity.notAfterGMT;

				var issuerInformation = cert.issuerName.split(",");
				var lastValue;

				for (index in issuerInformation) {
					value = issuerInformation[index];
					var b;

					if (value) {
						if (value.includes("CN=")) {
							certificationInformation.issuerCN = value.replace("CN=", "")
							lastValue = "CN=";
						}

						else if (value.includes("OU=")) {
							certificationInformation.issuerOU += value.replace("OU=", "")
							lastValue = "OU=";
						}

						else if (value.includes("O=")) {
							certificationInformation.issuerO = value.replace("O=", "")
							lastValue = "O=";
						}

						else if (value.includes("C=")) {
							certificationInformation.issuerC = value.replace("C=", "")
							lastValue = "C=";
						}
						else {
							if (lastValue == "OU=") {
								certificationInformation.issuerOU += value;
							}
						}
					}
				}
			}
		}
		catch (err) {
			//console.log("Error");
		}
	},

	print: function () {
		dump("Connection status: " + certificationInformation.status + "\n");
		dump("Security Info:\n");
		dump("\tSecurity state: " + certificationInformation.securityState + "\n");
		dump("\tSecurity description: " + certificationInformation.securityDescription + "\n");
		dump("\tSecurity error message: " + certificationInformation.errorMessage + "\n");
		dump("\tCommon name (CN) = " + certificationInformation.commonName + "\n");
		dump("\tOrganisation = " + certificationInformation.organization + "\n");
		dump("\tSHA1 fingerprint = " + certificationInformation.sha1Fingerprint + "\n");
		dump("\tIssuer = " + certificationInformation.issuerOrganization + "\n");
		dump("\tValid from " + certificationInformation.notBeforeGMT + "\n");
		dump("\tValid until " + certificationInformation.notAfterGMT + "\n");
		dump("\t(CN) " + certificationInformation.issuerCN + "\n");
		dump("\t(OU) " + certificationInformation.issuerOU + "\n");
		dump("\t(O) " + certificationInformation.issuerO + "\n");
		dump("\t(C) " + certificationInformation.issuerC + "\n");

	},

	clear: function () {
		certificationInformation.status = "";
		certificationInformation.securityState = "";
		certificationInformation.securityDescription = "";
		certificationInformation.errorMessage = "";
		certificationInformation.commonName = "";
		certificationInformation.organization = "";
		certificationInformation.sha1Fingerprint = "";
		certificationInformation.issuerOrganization = "";
		certificationInformation.notBeforeGMT = "";
		certificationInformation.notAfterGMT = "";
		certificationInformation.issuerCN = "";
		certificationInformation.issuerOU = "";
		certificationInformation.issuerO = "";
		certificationInformation.issuerC = "";
		certificationInformation.domainMismatch = "";
		certificationInformation.notValid = "";
		certificationInformation.untrusted = "";
	}
}

var language = {
	currentLanguage: '',
	languageData: '',
	de: {
		securelyEncryptedTransfer: "Daten werden gesichert übertragen.\n\nEs ist wichtig, dass Sie dennoch überprüfen, ob Sie dem Betreiber vertrauen bevor Sie Passwörter und andere persönlichen Daten eingeben",
		unencryptedTransfer: "Daten werden ungesichert übertragen.\n\nSie sollten auf dieser Webseite keine Passwörter oder anderen persönlichen Daten eingeben.",
		stateCurrentSite: "  Sie besuchen eine Seite des Betreibers: ",
		statelastSite: "  Sie besuchten eine Seite des Betreibers: ",
		securtyTransferNote: "Ihre Daten werden hier",
		unsafeTransfer: "unverschlüsselt",
		safeTransfer: "verschlüsselt",
		transfer: "übertragen.",
		note: "Überprüfen Sie diese Adresse auf ihre Richtigkeit.",
		securty: "Sicherheit:",
		levelLow: "Keine",
		levelMedium: "Mittel",
		levelHigh: "Hoch",
		httpsEV: "https mit EV Zertifikat"

	},
	en: {
		securelyEncryptedTransfer: "Data will be securely transmitted.\n\nIt is still important that you trust the operator before entering passwords and other personal data",
		unencryptedTransfer: "Data will be insecurely transmitted.\n\nYou should not enter passwords or other personal data on this site",
		stateCurrentSite: "  You visit one web page of the operator: ",
		statelastSite: "  You visited one web page of the operator: ",
		securtyTransferNote: "Your data will be transmitted in",
		unsafeTransfer: "unencrypted form",
		safeTransfer: "encrypted form",
		transfer: "here.",
		note: "Check this address for accuracy.",
		securty: "Security:",
		level: "Level",
		levelLow: "None",
		levelMedium: "Medium",
		levelHigh: "High",
		httpsEV: "https with EV certificate"
	},

	init: function () {
		this.currentLanguage = window.navigator.userLanguage || window.navigator.language;
		if (this.currentLanguage == "de") {
			this.languageData = this.de;
		}
		else {
			this.languageData = this.en;
		}
	},

	setSecurty: function () {
		document.getElementById("securtyL").value = this.languageData.securty;
	},

	setTextStateLastSite: function () {
		document.getElementById("visitStateL").value = this.languageData.statelastSite;
	},

	setTextStateCurrentSite: function () {
		document.getElementById("visitStateL").value = this.languageData.stateCurrentSite;
	},

	setTextNote: function () {
		document.getElementById("generalNoteL").value = this.languageData.note;
	},

	setInsecureSecurtyTransferNote: function () {
		document.getElementById("securtyTransferNoteL").value = this.languageData.securtyTransferNote;
		document.getElementById("securtyTransferStateL").value = this.languageData.unsafeTransfer;
		document.getElementById("securtyTransferNote2L").value = this.languageData.transfer;
	},

	setSecureSecurtyTransferNote: function () {
		document.getElementById("securtyTransferNoteL").value = this.languageData.securtyTransferNote;
		document.getElementById("securtyTransferStateL").value = this.languageData.safeTransfer;
		document.getElementById("securtyTransferNote2L").value = this.languageData.transfer;
	},

	setSecurtyLowDetails: function (protocolName, color) {
		document.getElementById("securtyStateL").value = "(" + protocolName + ")";
		document.getElementById("securtyLevelL").value = this.languageData.levelLow;
		document.getElementById("securtyStateL").style["color"] = color;
		document.getElementById("securtyLevelL").style["color"] = color;
	},

	setSecurtyMediumDetails: function (protocolName, color) {
		document.getElementById("securtyStateL").value = "(" + protocolName + ")";
		document.getElementById("securtyLevelL").value = this.languageData.levelMedium;
		document.getElementById("securtyStateL").style["color"] = color;
		document.getElementById("securtyLevelL").style["color"] = color;
	},

	setSecurtyHighDetails: function (color) {
		document.getElementById("securtyStateL").value = "(" + this.languageData.httpsEV + ")";
		document.getElementById("securtyLevelL").value = this.languageData.levelHigh;
		document.getElementById("securtyStateL").style["color"] = color;
		document.getElementById("securtyLevelL").style["color"] = color;
	}
}

var validation = {
	checkHttpsEV: function (url) {
		var req = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance(Components.interfaces.nsIXMLHttpRequest);
		req.open('GET', url, true);
		var channel = req.channel.QueryInterface(Components.interfaces.nsIPrivateBrowsingChannel);
		channel.setPrivate(true);

		req.onload = function (e) {
			certificationInformation.loadInformation(req);
		};

		req.send();
	},

	isURL: function (url) {
		if (url.match(/(ftp|http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?/)) {
			return true;
		}
		return false;
	}
}

var urlPruning = {
	init: function () {
		// The event can be DOMContentLoaded, pageshow, pagehide, load or unload.
		if (gBrowser) {
			gBrowser.addEventListener("DOMContentLoaded", this.onPageLoad, false);
			gBrowser.tabContainer.addEventListener("TabSelect", this.isTabChanged, false);
		}

		language.setTextNote();
		language.setSecurty();
		document.getElementById("DomainNameL").style.color = "#808000";
	},

	onPageLoad: function (aEvent) {
		var doc = aEvent.originalTarget; // doc is document that triggered the event
		urlPruning.pruning(doc);
	},

	isTabChanged: function (event) {
		//event.type is TabSelect and not DOMContentLoaded
		var doc = event.originalTarget.linkedBrowser.contentDocument;
		urlPruning.pruning(doc);
	},

	getDomainName: function (url) {
		var eTLDService = Components.classes["@mozilla.org/network/effective-tld-service;1"].getService(Components.interfaces.nsIEffectiveTLDService);
		var tempURI = Components.classes["@mozilla.org/network/io-service;1"].getService(Components.interfaces.nsIIOService).newURI("" + url, null, null);
		var isIP = String(url).match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g);

		if (isIP) {
			return isIP[0];
		}

		try {
			return eTLDService.getBaseDomain(tempURI);
		}
		catch (err) {
			return null;
		}
	},

	getProtocol: function (url) {
		var tmp = url.split(":");
		return tmp[0];
	},

	pruning: function (doc) {
		var win = doc.defaultView; // win is the window for the doc

		if (win != win.top) return;

		if (validation.isURL(doc.location.href)) {
			document.getElementById("DomainNameL").textContent = value = urlPruning.getDomainName(doc.location.href);
			var protocol = urlPruning.getProtocol(doc.location.href);

			if (protocol == "https") {
				validation.checkHttpsEV(doc.location.href);
				urlPruning.setHttpsInfo(protocol);
			}
			else if (protocol == "http") {
				urlPruning.setHttpInfo(protocol);
			}
			language.setTextStateCurrentSite();
		}
		else {
			language.setTextStateLastSite();
		}
	},

	setHttpsEVInfo: function () {
		language.setSecurtyHighDetails("green");
		language.setSecureSecurtyTransferNote();
	},

	setHttpsInfo: function (protocol) {
		language.setSecurtyMediumDetails(protocol, "orange");
		language.setSecureSecurtyTransferNote();
	},

	setHttpInfo: function (protocol) {
		language.setSecurtyLowDetails(protocol, "red");
		language.setInsecureSecurtyTransferNote();
	}
}

window.addEventListener("load", function load(event) {
	window.removeEventListener("load", load, false); //remove listener, no longer needed
	language.init();
	urlPruning.init();
}, false);
