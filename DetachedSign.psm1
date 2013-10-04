
<#
.Synopsis
   Creates a OpenPGP Detached signature for a file.
.DESCRIPTION
   Creates a OpenPGP Detached signature for a file given a secret key and its paraphrase.
.EXAMPLE
   $seckey = Get-PGPSecretKey -keyring $env:APPDATA\gnupg\secring.gpg -UserId "Carlos"
   PS C:\ > New-PGPDetachedSignature -SecretKey $seckey -File C:\evidence.txt -PassPhrase (Read-Host -AsSecureString) -Armour -OutFile C:\evidence.sig -Algorithm SHA1
#>
function New-PGPDetachedSignature
{
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullorEmpty()]
        [Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKey]$SecretKey,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$File,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage = "Secure String representing the passphase for the key.")]
        [securestring]$PassPhrase,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$OutFile,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('SHA1', "SHA256",'SHA384','SHA512','RIPEMD160')]
        [string]$HashAlgorithm = 'SHA512',

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [switch]$Armour
    )

    Begin
    {
    }
    Process
    {   
        if ($HashAlgorithm)
        {
            Write-Verbose "Using hash algorithm $($HashAlgorithm)"
        }
        else
        {
            Write-Verbose "Using prefered hash algorithm $($SecretKey.PreferedHash[0])"
            $HashAlgorithm = $SecretKey.PreferedHash[0]
        }

        Write-Verbose "Creating detached signature for $($File) as $($OutFile)"

        $instream = ($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File))
        $outstream = [System.IO.File]::Create(($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)))
        [PGPHelper.DetachedSignedFileProcessor]::CreateSignature($instream,
            $SecretKey,
            $outstream,
            ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PassPhrase))),  
            $Armour,
            $HashAlgorithm
        )
        $outstream.close()
        Write-Verbose "Detached signatured saved as $($OutFile)"

    }
    End
    {
    }
}

<#
.Synopsis
   Confirms the integrity of a file using an OpenPG Detached Signature.
.DESCRIPTION
   Confirms the integrity of a file using an OpenPG Detached Signature.
.EXAMPLE
   Confirm-PGPDetachedSignature -File C:\evidence.txt -Signature C:\evidence.sig -KeyRing $env:APPDATA\gnupg\pubring.gpg


Valid         : True
Created       : 10/4/2013 12:26:28 AM
KeyID         : DCC9422A3F0DB692
HashAlgorithm : Sha512
Version       : 4
Signature     : Org.BouncyCastle.Bcpg.OpenPgp.PgpSignature

#>
function Confirm-PGPDetachedSignature
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$File,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Signature,

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
        [PGPHelper.DetachedSignedFileProcessor]::VerifySignature($File, $Signature, $KeyRing)
    }
    End
    {
    }
}
