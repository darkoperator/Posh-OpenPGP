[void][Reflection.Assembly]::LoadFile("C:\Users\Carlos\Documents\Posh-OpenPGP\Source\PGPHelper\PGPHelper\bin\Debug\PGPHelper.dll")
[void][Reflection.Assembly]::LoadFile("C:\Users\Carlos\Documents\Posh-OpenPGP\Source\PGPHelper\PGPHelper\bin\Debug\BouncyCastle.CryptoExt.dll")


<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function New-PGPClearSignature
{
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKey]$SecretKey,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName='File')]
        [ValidateScript({Test-Path $_})]
        [string]$File,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName='Text')]
        [string]$Text,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage = "Secure String representing the passphase for the key.")]
        [securestring]$PassPhrase,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$OutFile,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('SHA1', "SHA256",'SHA384','SHA512','RIPEMD160')]
        [string]$Algorithm = 'SHA1'
    )

    Begin
    {
    }
    Process
    {

        if ($OutFile)
        {
            $outstream = [System.IO.File]::Create(($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)))
        }
        else
        {
            $outstream = New-Object System.IO.MemoryStream
        }

        switch ($PsCmdlet.ParameterSetName) 
        {
            'File'{
                $filecontent = Get-Content $file -Raw 
                $enc = [system.Text.Encoding]::ASCII
                $data1 = $enc.GetBytes($filecontent)
                $instream = New-Object System.IO.MemoryStream
                $instream.Write($data1,0,$data1.Length)
                $instream.Position = 0
            }
            'Text' {
                $enc = [system.Text.Encoding]::ASCII
                $data1 = $enc.GetBytes($Text)
                $instream = New-Object System.IO.MemoryStream
                $instream.Write($data1,0,$data1.Length)
                $instream.Position = 0
            }

        }
        
        [PGPHelper.ClearSignedFileProcessor]::SignFile($instream, 
        $SecretKey, 
        $outstream,
        ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PassPhrase))),  
        $Algorithm)
        
        if ($OutFile)
        {
            $outstream.Close()
        }
        else
        {
            [void]$outstream.Seek(0,"Begin")
            $readStream = New-Object System.IO.StreamReader $outstream
            while ($readStream.Peek() -ne -1)
            {
	            $readStream.ReadLine()
            }
        }

    }
    End
    {
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Confirm-PGPClearSignature
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName='File')]
        [ValidateScript({Test-Path $_})]
        [string]$File,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName='Text')]
        [string]$Text,

         [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [ValidateScript({Test-Path $_})]
        $KeyRing
    )

    Begin
    {
    }
    Process
    {
        switch ($PsCmdlet.ParameterSetName) 
        {
            'File'{
                $infile = [System.IO.File]::OpenRead(($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File)))
                $keyfile = [System.IO.File]::OpenRead(($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($KeyRing)))
                [PGPHelper.ClearSignedFileProcessor]::VerifyFile($infile,$keyfile)
                $infile.Close()
                $keyfile.Close()
            }
            'Text' {
                $enc = [system.Text.Encoding]::ASCII
                $data1 = $enc.GetBytes($Text)
                $instream = New-Object System.IO.MemoryStream
                $instream.Write($data1,0,$data1.Length)
                $instream.Position = 0
                $keyfile = [System.IO.File]::OpenRead(($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($KeyRing)))
                [PGPHelper.ClearSignedFileProcessor]::VerifyFile($instream,$keyfile)
                $keyfile.Close()
            }
        }
    }
    End
    {
    }
}


