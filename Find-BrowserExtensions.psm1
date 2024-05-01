function Find-BrowserExtensions {
    Param( 
    [Parameter(Position = 0)][String[]] $ComputerName = $null,
    [Parameter(Position = 1)][String] $Output = $null,
    [Parameter(Position = 2)][String] $Browser = $null,
    [Parameter(Position = 3)][String] $FindExtensionConfig = $null,
    [Parameter(Position = 4)][String] $crxCavatorReport = $null
    )

    $script:OutputForObjectArray = [Collections.ArrayList]::new()
    $script:crxOutArray = [Collections.ArrayList]::new()
    $script:BaseDirectory = "$env:USERPROFILE\"
    $script:BaseConfig = ".FindExtensionConfig.json"

    function New-BrowserOutput {
        param(
        [string]$Workstation = $null, 
        [string]$Browser = $null,
        [string]$ExtensionName = $null,
        [string]$ExtensionVersion = $null,
        [string]$ExtensionId = $null,
        [string]$ContentScripts = $null,
        [string]$ContentSecurityPolicy = $null,
        [string]$Permissions = $null
        )

        $BuildBrowserTable = [ordered]@{
            Workstation = $Workstation
            Browser = $Browser
            ExtensionName = $ExtensionName
            ExtensionVersion = $ExtensionVersion
            ExtensionId = $ExtensionId
            ContentScripts = $ContentScripts
            ContentSecurityPolicy = $ContentSecurityPolicy
            Permissions = $Permissions

        }
        $BuildBrowserOutputs = [PSCustomObject]$BuildBrowserTable 
        

        return $BuildBrowserOutputs
        
    }

    function New-CRXCavatorOut {
        param(
        [string]$Workstation = $null, 
        [string]$Browser = $null,
        [string]$ExtensionName = $null,
        [string]$ExtensionVersion = $null,
        [string]$ExtensionId = $null,
        [string]$ExtensionPermissions = $null,
        [string]$ExtensionCSPPolicy = $null,
        [string]$RiskTotalScore = $null,
        [string]$VulnerablitySummary = $null,
        [string]$VulnerablityCVE = $null,
        [string]$VulnerablitySeverity = $null,
        [string]$VulnerabiltyInfo = $null
        )

        $CRXCavatorBuildTable = [ordered]@{
        Workstation = $Workstation
        Browser = $Browser
        ExtensionName = $ExtensionName
        ExtensionVersion = $ExtensionVersion
        ExtensionId = $ExtensionId
        ExtensionPermissions = $ExtensionPermissions
        ExtensionCSPPolicy = $ExtensionCSPPolicy
        RiskTotalScore = $RiskTotalScore
        VulnerablitySummary = $VulnerablitySummary
        VulnerablityCVE = $VulnerablityCVE
        VulnerablitySeverity = $VulnerablitySeverity
        VulnerabiltyInfo = $VulnerabiltyInfo
        }
        $CRXCavatorBuildTableOut = [PSCustomObject]$CRXCavatorBuildTable 
        

        return $CRXCavatorBuildTableOut
    }

    function Get-ExtensionsEdge {
    param([string[]]$Computer)

    $Browser = "Edge"

    try {
        if($Computer -eq $env:COMPUTERNAME -or $Computer -eq "localhost") {
            $UserPaths = (Get-CimInstance win32_userprofile -ErrorAction Stop | Where-Object localpath -notmatch 'Windows' ).localpath
        } else {
            $UserPaths = (Get-CimInstance win32_userprofile -ComputerName $Computer -ErrorAction Stop | Where-Object localpath -notmatch 'Windows' ).localpath
        }
    }
    catch [System.Runtime.InteropServices.COMException] {
        if($_.Exception.ErrorCode -eq 0x800706BA) {
            Write-Output ("Computer: $Computer" + "`n" + "Status: Unavailable" + "`n" + "Reason: RPCServer Unavailable")
        }
    }
    $Users = $UserPaths | Split-Path -Leaf -ErrorAction SilentlyContinue
    foreach ($User in $Users) {
        $EdgeExt = Get-ChildItem -Path "\\$($Computer)\c$\Users\$($User)\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\" -ErrorAction SilentlyContinue
            if ($onError) {
                $onError[0].TargetObject
            }
            foreach ($EdgeFolder in $EdgeExt) {
                $varEdgeFolders = Get-ChildItem $EdgeFolder.FullName
                foreach ($verEdgeFolder in $varEdgeFolders) {
                    if (Test-Path -Path ($verEdgeFolder.FullName + '\manifest.json')) {
                        $EdgeManifest = Get-Content ($verEdgeFolder.FullName + '\manifest.json') | ConvertFrom-Json
                        if ($EdgeManifest.name -like '__MSG*') {
                            $EdgeAppId = ($EdgeManifest.name -replace '__MSG_','').Trim('_')

                            '\_locales\en_US\', '\_locales\en\' | ForEach-Object {
                                if (Test-Path -Path ($verEdgeFolder.Fullname + $_ + 'messages.json')) {
                                    $EdgeAppManifest = Get-Content ($verEdgeFolder.Fullname + $_ +'messages.json') | ConvertFrom-Json
                                    @($EdgeAppManifest.appName.message, $EdgeAppManifest.extName.message, $EdgeAppManifest.extensionName.message, $EdgeAppManifest.app_name.message, $EdgeAppManifest.application_title.message, $EdgeAppManifest.$EdgeAppId.message) | ForEach-Object { if (($_) -and (-not($EdgeExtName))) { $EdgeExtName = $_ }}
                                }
                            }

                        }
                        else {
                            $EdgeExtName = $EdgeManifest.name
                        }
                      
                        if ($($EdgeFolder.name) -notin $script:config.Edge.ExtensionId) {
                            $OutputSend = New-BrowserOutput -Workstation $Computer -Browser $Browser -ExtensionName $EdgeExtName -ExtensionVersion $EdgeManifest.version -ExtensionId $EdgeFolder.name -ContentScripts $($EdgeManifest.content_scripts.js) -ContentSecurityPolicy $($EdgeManifest.content_security_policy) -Permissions $($EdgeManifest.permissions)
                            $null = $OutputForObjectArray.Add($OutputSend)
                            $OutputSend
                        }

                        if ($EdgeExtName) {
                            Remove-Variable -Name EdgeExtName
                        }

                    }

                }

            }
        }
    }

    function Get-ExtensionsChrome {
    param([string[]]$Computer)

    $Browser = "Chrome"

    try {
        if($Computer -eq $env:COMPUTERNAME -or $Computer -eq "localhost") {
            $UserPaths = (Get-CimInstance win32_userprofile -ErrorAction Stop | Where-Object localpath -notmatch 'Windows' ).localpath
        } else {
            $UserPaths = (Get-CimInstance win32_userprofile -ComputerName $Computer -ErrorAction Stop | Where-Object localpath -notmatch 'Windows' ).localpath
        }
    }
    catch [System.Runtime.InteropServices.COMException] {
        if($_.Exception.ErrorCode -eq 0x800706BA) {
            Write-Output ("Computer: $Computer" + "`n" + "Status: Unavailable" + "`n" + "Reason: RPCServer Unavailable")
        }
    }

    $Users = $UserPaths | Split-Path -Leaf -ErrorAction SilentlyContinue

    foreach ($User in $Users) {
        $UserExt = Get-ChildItem -Path "\\$($Computer)\c$\Users\$($User)\AppData\Local\Google\Chrome\User Data\Default\Extensions\" -ErrorAction SilentlyContinue
        foreach ($Folders in $UserExt){
            $varFolders = Get-ChildItem $Folders.FullName
                foreach ($verFolder in $varFolders){
                    if (Test-Path -Path ($verFolder.FullName + '\manifest.json')) {
                        $Manifest = Get-Content ($verFolder.FullName + '\manifest.json') | ConvertFrom-Json
                        if ($Manifest.name -like '__MSG*') {
                            $AppId = ($Manifest.name -replace '__MSG_','').Trim('_')
                            '\_locales\en_US\', '\_locales\en\' | ForEach-Object {
                                if (Test-Path -Path ($verFolder.Fullname + $_ + 'messages.json')) {
                                    $AppManifest = Get-Content ($verFolder.Fullname + $_ +'messages.json') | ConvertFrom-Json
                                    @($AppManifest.appName.message, $AppManifest.extName.message, $AppManifest.extensionName.message, $AppManifest.app_name.message, $AppManifest.application_title.message, $AppManifest.$AppId.message) | ForEach-Object { if (($_) -and (-not($ExtName))) { $ExtName = $_ }}
                                }
                            }
                        } 
                        else {
                            $ExtName = $Manifest.name
                        }
       
                        if ($($Folders.name) -notin $script:config.Chrome.ExtensionId) {
                            $OutputSend = New-BrowserOutput -Workstation $Computer -Browser $Browser -ExtensionName $ExtName -ExtensionVersion $Manifest.version -ExtensionId $Folders.name -ContentScripts $($Manifest.content_scripts.js) -ContentSecurityPolicy $($Manifest.content_security_policy) -Permissions $($Manifest.permissions)
                            $null = $OutputForObjectArray.Add($OutputSend)
                            $OutputSend
                        }

                        if ($ExtName) {
                            Remove-Variable -Name ExtName
                        }

                    }

                }

        }
    
   
    }

    }

    function Get-ExtensionsBrave {
        param([string[]]$Computer)
    
        $Browser = "Brave"
    
        try {
            if($Computer -eq $env:COMPUTERNAME -or $Computer -eq "localhost") {
                $UserPaths = (Get-CimInstance win32_userprofile -ErrorAction Stop | Where-Object localpath -notmatch 'Windows' ).localpath
            } else {
                $UserPaths = (Get-CimInstance win32_userprofile -ComputerName $Computer -ErrorAction Stop | Where-Object localpath -notmatch 'Windows' ).localpath
            }
        }
        catch [System.Runtime.InteropServices.COMException] {
            if($_.Exception.ErrorCode -eq 0x800706BA) {
                Write-Output ("Computer: $Computer" + "`n" + "Status: Unavailable" + "`n" + "Reason: RPCServer Unavailable")
            }
        }
    
        $Users = $UserPaths | Split-Path -Leaf -ErrorAction SilentlyContinue
    
        foreach ($User in $Users) {
            $UserExt = Get-ChildItem -Path "\\$($Computer)\c$\Users\$($User)\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Extensions\" -ErrorAction SilentlyContinue
            foreach ($Folders in $UserExt){
                $varFolders = Get-ChildItem $Folders.FullName
                    foreach ($verFolder in $varFolders){
                        if (Test-Path -Path ($verFolder.FullName + '\manifest.json')) {
                            $Manifest = Get-Content ($verFolder.FullName + '\manifest.json') | ConvertFrom-Json
                            if ($Manifest.name -like '__MSG*') {
                                $AppId = ($Manifest.name -replace '__MSG_','').Trim('_')
                                '\_locales\en_US\', '\_locales\en\' | ForEach-Object {
                                    if (Test-Path -Path ($verFolder.Fullname + $_ + 'messages.json')) {
                                        $AppManifest = Get-Content ($verFolder.Fullname + $_ +'messages.json') | ConvertFrom-Json
                                        @($AppManifest.appName.message, $AppManifest.extName.message, $AppManifest.extensionName.message, $AppManifest.app_name.message, $AppManifest.application_title.message, $AppManifest.$AppId.message) | ForEach-Object { if (($_) -and (-not($ExtName))) { $ExtName = $_ }}
                                    }
                                }
                            } 
                            else {
                                $ExtName = $Manifest.name
                            }
           
                            if ($($Folders.name) -notin $script:config.Chrome.ExtensionId) {
                                $OutputSend = New-BrowserOutput -Workstation $Computer -Browser $Browser -ExtensionName $ExtName -ExtensionVersion $Manifest.version -ExtensionId $Folders.name -ContentScripts $($Manifest.content_scripts.js) -ContentSecurityPolicy $($Manifest.content_security_policy) -Permissions $($Manifest.permissions)
                                $null = $OutputForObjectArray.Add($OutputSend)
                                $OutputSend
                            }
    
                            if ($ExtName) {
                                Remove-Variable -Name ExtName
                            }
    
                        }
    
                    }
    
            }
        
       
        }
    
    }

    function Get-ExtensionsFirefox {
    param( [string[]]$Computer)

    $Browser = "Firefox"

    try {
        if($Computer -eq $env:COMPUTERNAME -or $Computer -eq "localhost") {
            $UserPaths = (Get-CimInstance win32_userprofile -ErrorAction Stop | Where-Object localpath -notmatch 'Windows' ).localpath
        } else {
            $UserPaths = (Get-CimInstance win32_userprofile -ComputerName $Computer -ErrorAction Stop | Where-Object localpath -notmatch 'Windows' ).localpath
        }
    } 
    catch [System.Runtime.InteropServices.COMException] {
        if($_.Exception.ErrorCode -eq 0x800706BA) {
            Write-Output ("Computer: $Computer" + "`n" + "Status: Unavailable" + "`n" + "Reason: RPCServer Unavailable")
        }
    }

    $FirefoxInstalled = Get-ChildItem "\\$Computer\c$\Program Files\Mozilla Firefox\firefox.exe" -ErrorAction SilentlyContinue
    
    if (!($FirefoxInstalled)) {
        Write-Output "[+] Firefox not present on $Computer"
        break;
    }
    $Users = $UserPaths | Split-Path -Leaf -ErrorAction SilentlyContinue

    foreach ($User in $Users) {
        $BuildFFExtJsonFile = Get-ChildItem "\\$Computer\c$\Users\$($User)\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release-*\extensions.json"
        if ($BuildFFExtJsonFile.Exists) {
            $jsonExtensionFF = Get-Content $BuildFFExtJsonFile.FullName -Raw | ConvertFrom-Json 
            foreach($j in $jsonExtensionFF.addons) {
                #only reporting on user added extensions. ignoring builtin stuff
                if($j.rootURI -notlike "jar:file:///C:/Program%20Files/Mozilla%20Firefox/browser/features/*" -and $j.rootURI -notlike "resource://*" ) {
                    $OutputSend = New-BrowserOutput -Workstation $Computer -Browser $Browser -ExtensionName $j.defaultLocale.name -ExtensionVersion $j.version -ExtensionId $j.id
                    $null = $OutputForObjectArray.Add($OutputSend)
                    $OutputSend
                }
            }
        }
    }

    }

    function New-ThreatIntelOutput {
        $BaseConfigPath = "$BaseDirectory$BaseConfig"
        $script:Config = Get-Content $BaseConfigPath -Raw | ConvertFrom-Json

        if ($Script:Config.crxCavatorApiKey.Key) {
            $defAuthHeader = @{
                'API-Key'= $Script:Config.crxCavatorApiKey.Key
                'Content-Type'= 'application/json'
            }
            foreach ($Ext in $script:OutputForObjectArray) {          
                $crxcavatorLink = "https://api.crxcavator.io/v1/report/$($Ext.ExtensionId)/$($Ext.ExtensionVersion)?platform=$($Ext.Browser)"
                $crxResponse = Invoke-RestMethod $crxcavatorLink -Headers $defAuthHeader -Method Get
                $crxOutSend = New-CRXCavatorOut -Workstation $($Ext.Workstation) -Browser $($Ext.Browser) -ExtensionName $($Ext.ExtensionName) -ExtensionVersion $($Ext.ExtensionVersion) `
                                                -ExtensionId ($Ext.ExtensionId) -ExtensionPermissions $($crxResponse.data.manifest.permissions)`
                                                -ExtensionCSPPolicy $($crxResponse.data.manifest.content_security_policy) -RiskTotalScore $($crxResponse.data.risk.total)`
                                                -VulnerablitySummary $($crxResponse.data.retire.results.vulnerabilities.identifiers.summary) `
                                                -VulnerablityCVE $($crxResponse.data.retire.results.vulnerabilities.identifiers) `
                                                -VulnerablitySeverity $($crxResponse.data.retire.results.vulnerabilities.severity) `
                                                -VulnerabiltyInfo $($crxResponse.data.retire.results.vulnerabilities.info)
                $null = $crxOutArray.Add($crxOutSend)
                $crxOutSend
            }
        }
    }

    switch ($Browser.ToLower()) {
        "edge" {Get-ExtensionsEdge -Computer $ComputerName}
        "firefox" {Get-ExtensionsFirefox -Computer $ComputerName}
        "chrome" {Get-ExtensionsChrome -Computer $ComputerName}
        "brave" {Get-ExtensionsBrave -Computer $ComputerName}
    default {
        #ALL
        Get-ExtensionsEdge -Computer $ComputerName
        Get-ExtensionsChrome -Computer $ComputerName
        Get-ExtensionsFirefox -Computer $ComputerName 
        Get-ExtensionsBrave -Computer $ComputerName}
    }
    

    if($Output) {
        $OutputForObjectArray |
        ConvertTo-Csv -NoTypeInformation |
        Out-File -FilePath $Output -Append -ErrorAction Stop
    }

    if($FindExtensionConfig) {
        $BaseConfigPath = "$BaseDirectory$BaseConfig"
        $script:Config = Get-Content $BaseConfigPath -Raw | ConvertFrom-Json
    }

    if($crxCavatorReport){
        New-ThreatIntelOutput
    }

    if($crxCavatorReport -and $Output) {
        $crxOutArray |
        ConvertTo-Csv -NoTypeInformation |
        Out-File -FilePath $Output -Append -ErrorAction Stop
    }
}
