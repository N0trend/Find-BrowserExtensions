# Find-BrowserExtensions
Browser Extension Discovery with optional CRXcavator report

This Powershell module was created to gather Chrome, Edge and Firefox browser extension details on a remote or local windows machine.

Can be used to find indicators of malicious (or overly permissioned) browser extensions on remote or local machines. Could also be leveraged to take advantage of a vulnerability within the extension based on report. The crxCavator report functionality expands on vulnerability and permission details.

Note, to use the crxcavator functionality you'll need an API key in the config file. API key is free from their site. 

Sample config file in this repo to copy and use.

## Usage
### Find-BrowserExtensions 

Import:

```
PS C:\> git clone https://github.com/N0trend/Find-BrowserExtensions.git
PS C:\> Import-Module .\Find-BrowsersExtensions.psm1
PS C:\> Find-BrowserExtensions -ComputerName localhost
```

Straight to console:

```
Find-BrowserExtensions -ComputerName $env:COMPUTERNAME -Browser Chrome
Find-BrowserExtensions -ComputerName $env:COMPUTERNAME -Browser Firefox
Find-BrowserExtensions -ComputerName $env:COMPUTERNAME -Browser Edge
```

Example output:

```
Workstation           : localhost
Browser               : Chrome
ExtensionName         : uBlock Origin
ExtensionVersion      : 1.44.0
ExtensionId           : cjpalhdlnbpafiamejdnhcphjbkeiagm
ContentScripts        : /js/vapi.js /js/vapi-client.js /js/contentscript.js /js/scriptlets/subscriber.js
ContentSecurityPolicy : script-src 'self'; object-src 'self'
Permissions           : contextMenus privacy storage tabs unlimitedStorage webNavigation webRequest webRequestBlocking <all_urls>

Workstation           : localhost
Browser               : Chrome
ExtensionName         : LastPass: Free Password Manager
ExtensionVersion      : 4.101.1.3
ExtensionId           : hdokiejnpimakedhajhdlcegeplioahd
ContentScripts        : onloadwff.js web-client-content-script.js acctsiframe-content-script.js extension-detection-content-script.js fedlogin-content-script.js
ContentSecurityPolicy : default-src 'self'; frame-src 'self' https://lastpass.com/ https://lastpass.eu; connect-src 'self' https://lastpass.com/ https://accounts.lastpass.com
                        wss://*.lastpass.com wss://*.lastpass.eu https://*.lastpass.com https://lastpass.com https://lastpass.eu https://login.microsoftonline.com
                        https://graph.microsoft.com https://login.microsoftonline.us https://graph.microsoft.us https://*.oktapreview.com https://*.okta.com https://*.okta-emea.com
                        https://*.pingone.com https://*.pingone.ca https://*.pingone.eu https://*.pingone.asia https://accounts.google.com https://www.googleapis.com
                        https://openidconnect.googleapis.com https://content.googleapis.com https://*.onelogin.com; img-src 'self' data: blob: https://lastpass.com/ chrome://favicon
                        https://images.mxpnl.com https://content.product.lastpass.com; style-src 'self' 'unsafe-inline' https://content.product.lastpass.com https://lastpass.com/ ;
                        child-src 'self' ; script-src 'self' ;
Permissions           : tabs idle notifications contextMenus unlimitedStorage webRequest webNavigation webRequestBlocking http://*/* https://*/* chrome://favicon/*
```

Output to a filepath:

```
Find-BrowserExtensions -ComputerName $env:COMPUTERNAME -Browser Chrome -Output C:\Filepath\Here\ChromeOut.csv
```


If you want to ignore extension ids and/or use a crxCavatorApiKey update the `.FindExtensionConfig.json` file (config in repo). By default it reads from: `$env:USERPROFILE\.FindExtensionConfig.json` 

Output with crxCavator results:
```
Find-BrowserExtensions -ComputerName $env:COMPUTERNAME -Browser Chrome -crxCavatorReport true -Output C:\Filepath\Here\ChromeOut.csv
```

Example Output:
```
Workstation          : localhost
Browser              : Chrome
ExtensionName        : EditThisCookie
ExtensionVersion     : 1.6.3
ExtensionId          : fngmhnnpilhplaeedifhccceomclgfbg
ExtensionPermissions : tabs <all_urls> cookies contextMenus notifications clipboardWrite webRequest webRequestBlocking
ExtensionCSPPolicy   : script-src 'self' https://ssl.google-analytics.com; object-src 'self'
RiskTotalScore       : 615
VulnerablitySummary  : jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution Regex in
                       its jQuery.htmlPrefilter sometimes may introduce XSS Regex in its jQuery.htmlPrefilter sometimes may introduce XSS
VulnerablityCVE      :
VulnerablitySeverity : medium medium medium
VulnerabiltyInfo     : https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/ https://nvd.nist.gov/vuln/detail/CVE-2019-11358
                       https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
                       https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
```
