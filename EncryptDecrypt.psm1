<#
.Synopsis
   Protects a file using OpenPGP and encryps the unencyption key with a given Public Key.
.DESCRIPTION
   Protects a file using OpenPGP and encryps the unencyption key with a given Public Key.
.EXAMPLE
   $pubkeys = Get-PGPPublicKey -KeyRing $env:APPDATA\gnupg\pubring.gpg -UserId "Carlos","Marta" -MatchPartial
   PS c:\> Protect-PGpEncryptedFile -File C:\evidence.txt -OutFile C:\evidence.pgp -PublicKey $pubkeys -Armour -IntegrityCheck
#>
function Protect-PGPEncryptedFile
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
        [ValidateSet('Uncompressed', 'Zip','Zlib','BZip2')]
        [string]$Compression,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [switch]$Armour,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [switch]$IntegrityCheck,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('IDEA',
            '3DES',
            'CAST5',
            'BlowFish',
            'TowFish',
            'DES',
            'AES128',
            'AES196',
            'AES256')]
        [string]$SymmetricAlgorithm
    )

    Begin
    {
    }
    Process
    {
        $outstream = [System.IO.File]::Create(($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)))

        # Select compression algorithm.
        if ($Compression)
        {
            Write-Verbose "Using selected compression algorithm $($Compression)."

        }
        else
        {
            # Check if we got more that one public key to work with.
            if ($PublicKey.length -eq 1)
            {
                # if we only got one public key lets see if it has preferred compression algos
                if ($PublicKey.PreferedCompression -ne 0)
                {
                    Write-Verbose "Using preferred compression algorithm $($PublicKey.PreferedCompression[0])."
                    $compression = $PublicKey.PreferedCompression[0]
                }
                else
                {
                    Write-Verbose 'Key does not have preferred compression algorithm usin Zip'
                    $compression = 'Zip'
                }
            }
            else
            {
                # If we have more than one key we use the settings of the first one
                if ($PublicKey[0].PreferedCompression -ne 0)
                {
                    Write-Verbose "Using preferred compression algorithm $($PublicKey[0].PreferedCompression[0])."
                    $compression = $PublicKey[0].PreferedCompression[0]
                }
                else
                {
                    Write-Verbose 'Key does not have preferred compression algorithm usin Zip'
                    $compression = 'Zip'
                }
            }
        }

        # Select Symmetric Algorithm
        if ($SymmetricAlgorithm)
        {
            Write-Verbose "Using selected symmetric algorithm $($SymmetricAlgorithm)."

        }
        else
        {
            if ($PublicKey.length -eq 1)
            {
                if ($PublicKey.PreferedSymmetric -ne 0)
                {
                    Write-Verbose "Using preferred symmetric algorithm $($PublicKey.PreferedSymmetric[0])."
                    $SymmetricAlgorithm = $PublicKey.PreferedSymmetric[0]
                }
                else
                {
                    Write-Verbose 'Key does not have preferred symmetric algorithm using AES256'
                    $SymmetricAlgorithm = 'AES256'
                }
            }
            else
            {
                if ($PublicKey[0].PreferedSymmetric -ne 0)
                {
                    Write-Verbose "Using preferred symmetric algorithm $($PublicKey[0].PreferedSymmetric[0])."
                    $SymmetricAlgorithm = $PublicKey[0].PreferedSymmetric[0]
                }
                else
                {
                    Write-Verbose 'Key does not have preferred symmetric algorithm using AES256'
                    $SymmetricAlgorithm = 'AES256'
                }
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
        HelpMessage = 'Secure String representing the pass-phase for the key.')]
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


<#
.Synopsis
   Encrypts a file using OpenPGP Symmetric encryption.
.DESCRIPTION
   Encrypts a file using OpenPGP Symmetric encryption.
.EXAMPLE
   Protect-PGPSymmetricEncryptedFile -File .\notes.txt -OutFile .\notes1.enc -PassPhrase (Read-Host -AsSecureString) -Verbose -Armour
VERBOSE: Using selected compression algorithm Zip.
VERBOSE: Using selected symmetric algorithm AES256.
VERBOSE: Encrypting file .\notes.txt
VERBOSE: File has been encrypted as .\notes1.enc
#>

function Protect-PGPSymmetricEncryptedFile
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
        [securestring]$PassPhrase,
       
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Uncompressed', 'Zip','Zlib','BZip2')]
        [string]$Compression = 'Zip',

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [switch]$Armour,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('IDEA',
            '3DES',
            'CAST5',
            'BlowFish',
            'TowFish',
            'DES',
            'AES128',
            'AES196',
            'AES256')]
        [string]$SymmetricAlgorithm = 'AES256'
    )

    Begin
    {
    }
    Process
    {
        $outstream = [System.IO.File]::Create(($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)))
        $instream = [System.IO.File]::OpenRead((Resolve-Path $file).Path)
        Write-Verbose "Using selected compression algorithm $($Compression)."
        Write-Verbose "Using selected symmetric algorithm $($SymmetricAlgorithm)."
        Write-Verbose "Encrypting file $($File)"

        [PGPHelper.SymmetricFileProcessor]::Encrypt($instream,
            $outstream, 
            $SymmetricAlgorithm, 
            ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PassPhrase))), 
            $Armour,
            $Compression, 
            $true)
        $outstream.close()
        $instream.Close()

        Write-Verbose "File has been encrypted as $($OutFile)"
    }
    End
    {
    }
}



<#
.Synopsis
   Decrypts a OpenPGP symmetrically encrypted file.
.DESCRIPTION
   Decrypts a OpenPGP symmetrically encrypted file.
.EXAMPLE
   Unprotect-PGPSymmetricEncryptedFile -File .\notes.enc -OutFile .\notes1.txt -PassPhrase (Read-Host -AsSecureString) -Verbose
VERBOSE: Encrypting file C:\Users\Carlos\Desktop\notes.enc
VERBOSE: File has been decrypted as .\notes1.txt
#>

function Unprotect-PGPSymmetricEncryptedFile
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [string]$File,
        
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [string]$OutFile,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
        [securestring]$PassPhrase
    )

    Begin
    {
    }
    Process
    {
        Write-Verbose "Encrypting file $((Resolve-Path $file).Path)"

        [string]$outstream = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
        $instream = [System.IO.File]::OpenRead((Resolve-Path $file).Path)

        [PGPHelper.SymmetricFileProcessor]::DecryptFile($instream,
            $outstream, 
            ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PassPhrase))))

        $instream.Close()

        Write-Verbose "File has been decrypted as $($OutFile)"
    }
    End
    {
    }
}

