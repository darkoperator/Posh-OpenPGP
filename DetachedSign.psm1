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
        [string]$Algorithm = 'SHA512',

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [switch]$Armour
    )

    Begin
    {
    }
    Process
    {   
        $instream = ($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File))
        $outstream = [System.IO.File]::Create(($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)))
        [PGPHelper.DetachedSignedFileProcessor]::CreateSignature($instream,
            $SecretKey,
            $outstream,
            ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PassPhrase))),  
            $Armour,
            $Algorithm
        )
        $outstream.close()

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

$secretkey = [PGPHelper.KeyUtilities]::ReadSecretKey("C:\BF6A6538A15ACC5E_sec.pgp")
New-PGPDetachedSignature -File C:\Users\Carlos\Desktop\jre1.7.0_21-c.msi -SecretKey $secretkey -PassPhrase (Read-Host -AsSecureString) -OutFile C:\Users\Carlos\Desktop\jre1.7.0_21-c.sig 
Confirm-PGPDetachedSignature -File C:\Users\Carlos\Desktop\jre1.7.0_21-c.msi -Signature C:\Users\Carlos\Desktop\jre1.7.0_21-c.sig -KeyRing C:\Users\Carlos\AppData\Roaming\gnupg\pubring.gpg