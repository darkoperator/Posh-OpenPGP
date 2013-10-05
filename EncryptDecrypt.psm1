<#
.Synopsis
   Protects a file using OpenPGP and encryps the unencyption key with a given Public Key.
.DESCRIPTION
   Protects a file using OpenPGP and encryps the unencyption key with a given Public Key.
.EXAMPLE
   $pubkeys = Get-PGPPublicKey -KeyRing $env:APPDATA\gnupg\pubring.gpg -UserId "Carlos","Marta" -MatchPartial
   PS c:\> Protect-PGpEncryptedFile -File C:\evidence.txt -OutFile C:\evidence.pgp -PublicKey $pubkeys -Armour -IntegrityCheck
#>
function Protect-PGpEncryptedFile
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        $File,
        
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [string]$OutFile,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
        $PublicKey,
       
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Uncompressed', "Zip",'Zlib','BZip2')]
        [string]$Compression,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [switch]$Armour,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [switch]$IntegrityCheck,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("IDEA",
            "3DES",
            "CAST5",
            "BlowFish",
            "TowFish",
            "DES",
            "AES128",
            "AES196",
            "AES256",
            "SAFER")]
        [string]$SymmetricAlgorithm
    )

    Begin
    {
    }
    Process
    {
        $outstream = [System.IO.File]::Create(($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)))
        if ($Compression)
        {
            Write-Verbose "Using selected compression algorithm $($Compression)."

        }
        else
        {
            if ($PublicKey.length -eq 1)
            {
                Write-Verbose "Using prefered compression algorithm $($PublicKey.PreferedCompression[0])."
                $compression = $PublicKey.PreferedCompression[0]
            }
            else
            {
                Write-Verbose "Using prefered compression algorithm $($PublicKey[0].PreferedCompression[0])."
                $compression = $PublicKey[0].PreferedCompression[0]
            }
        }

        if ($SymmetricAlgorithm)
        {
            Write-Verbose "Using selected symmetric algorithm $($SymmetricAlgorithm)."

        }
        else
        {
            if ($PublicKey.length -eq 1)
            {
                Write-Verbose "Using prefered compression algorithm $($PublicKey.PreferedSymmetric[0])."
                $SymmetricAlgorithm = $PublicKey.PreferedSymmetric[0]
            }
            else
            {
                Write-Verbose "Using prefered compression algorithm $($PublicKey[0].PreferedSymmetric[0])."
                $SymmetricAlgorithm = $PublicKey[0].PreferedSymmetric[0]
            }
        }
        Write-Verbose "Encrypting file $($File)"
        [PGPHelper.PGPEncryptDecrypt]::EncryptFile($outstream, (Resolve-Path $file).Path, $PublicKey, $Armour, $IntegrityCheck, $Compression, $SymmetricAlgorithm) 
        $outstream.close()
        Write-Verbose "File has been encrypted as $($OutFile)"
    }
    End
    {
    }
}

<#
.Synopsis
   Unprotects a OpenPGP encrypted file given the Secret Key and Passphrase.
.DESCRIPTION
   Unprotects a OpenPGP encrypted file given the Secret Key and Passphrase.
.EXAMPLE
   $sec =  Get-PGPSecretKey -KeyRing $env:APPDATA\gnupg\secring.gpg -UserId "Carlos" -MatchPartial
   PS C:\ >Unprotect-PGPEncryptedFile -File C:\evidence.pgp -SecretKey $sec -PassPhrase (Read-Host -AsSecureString) -OutFile $env:USERPROFILE\Desktop\evidence.txt

.EXAMPLE
   Another example of how to use this cmdlet
#>
function Unprotect-PGPEncryptedFile
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        $File,
        
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
        [string]$OutFile,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
        [ValidateNotNullorEmpty()]
        [Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKey]$SecretKey,


        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=3,
        HelpMessage = "Secure String representing the passphase for the key.")]
        [securestring]$PassPhrase
    )

    Begin
    {
    }
    Process
    {

        $instream = [System.IO.File]::OpenRead(($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File)))
        [PGPHelper.PGPEncryptDecrypt]::DecryptFile($instream, 
            $SecretKey, ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PassPhrase))),
            ($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)))
        $instream.Close()
    }
    End
    {
    }
}

