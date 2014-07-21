
<#
.Synopsis
   Clear OpenPGP Signs a text file or string.
.DESCRIPTION
   Clear OpenPGP Signs a text file or string. In multi string a carrige return must be added to to the end
   or an empty line must be present for proper formating.
.EXAMPLE
   New-PGPClearSignature -SecretKey $seckey -File C:\evidence.txt -PassPhrase (Read-Host -AsSecureString) -OutFile C:\evidence.asc
.EXAMPLE
   $seckey = Get-PGPSecretKey -KeyRing $env:APPDATA\gnupg\secring.gpg -UserId "darkoperator"
PS C:\> $message = New-PGPClearSignature -SecretKey $seckey -Text "This is my ubber secret message`n" -PassPhrase (Read-Host -AsSecureString)
PS C:\> $creds = Get-Credential carlos_perez@darkoperator.com
PS C:\> $param = @{
    SmtpServer = 'smtp.gmail.com'
    Port = 587
    UseSsl = $true
    Credential  = $creds
    From = 'carlos_perez@darkoperator.com'
    To = 'cperezotero@gmail.com'
    Subject = 'My Secret Message'
    Body = "$($message -join "`r`n")"
}
 
PS C:\> Send-MailMessage @param -Verbose

Sends a Signed OpenPGP Email
#>
function New-PGPClearSignature
{
    [CmdletBinding(DefaultParameterSetName = 'File')]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKey]$SecretKey,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName='File')]
        [ValidateScript({Test-Path -Path $_})]
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
        [string]$HashAlgorithm
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
            $outstream = New-Object -TypeName System.IO.MemoryStream
        }

        switch ($PsCmdlet.ParameterSetName) 
        {
            'File'{
                Write-Verbose "Signing file $($File)"
                $filecontent = Get-Content $file -Raw 
                $enc = [system.Text.Encoding]::ASCII
                $data1 = $enc.GetBytes($filecontent)
                $instream = New-Object System.IO.MemoryStream
                $instream.Write($data1,0,$data1.Length)
                $instream.Position = 0
            }
            'Text' {
                Write-Verbose "Signing provided string"
                $enc = [system.Text.Encoding]::ASCII
                $data1 = $enc.GetBytes($Text)
                $instream = New-Object System.IO.MemoryStream
                $instream.Write($data1,0,$data1.Length)
                $instream.Position = 0
            }

        }
        
        if ($HashAlgorithm)
        {
            Write-Verbose "Using hash algorithm $($HashAlgorithm)"
        }
        else
        {
            Write-Verbose "Using preferred hash algorithm $($SecretKey.PreferedHash[0])"
            $HashAlgorithm = $SecretKey.PreferedHash[0]
        }

        [PGPHelper.ClearSignedFileProcessor]::SignFile($instream, 
        $SecretKey, 
        $outstream,
        ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PassPhrase))),  
        $HashAlgorithm)

        if ($OutFile)
        {
            Write-Verbose "Signed content created at $($OutFile)"
            $outstream.Close()
        }
        else
        {
            Write-Verbose "Output of signed content sent to Console"
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
   Verifies an OpenPGP clearsigned file or string.
.DESCRIPTION
   Verifies an OpenPGP clearsigned file or string.
.EXAMPLE
   Confirm-PGPClearSignature -File C:\evidence.asc -KeyRing $env:APPDATA\gnupg\pubring.gpg


Valid         : True
Created       : 10/4/2013 1:10:16 AM
KeyID         : 48E6AA1C3ED92AC3
HashAlgorithm : Sha512
Version       : 4
Signature     : Org.BouncyCastle.Bcpg.OpenPgp.PgpSignature
#>
function Confirm-PGPClearSignature
{
    [CmdletBinding(DefaultParameterSetName='File')]
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

