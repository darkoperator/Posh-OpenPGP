
<#
.Synopsis
   Get a specified or all private keys from a OpenPGP key ring file.
.DESCRIPTION
   Get a specified or all private keys from a OpenPGP key ring file.
.EXAMPLE
   Get-PGPSecretKey -KeyRing C:\95b4851b599cb231_sec.pgp -Id 95B4851B599CB231
   

Id                     : 95B4851B599CB231
IsSigningKey           : True
IsMasterKey            : True
KeyEncryptionAlgorithm : Cast5
KeyId                  : -7659350713736318415
PublicKey              : Org.BouncyCastle.Bcpg.OpenPgp.PgpPublicKey
UserIds                : {Carlos Perez <carlos@infosectactico.com>}
UserAttributes         : {}
#>
function Get-PGPSecretKey
{
    [CmdletBinding()]
    [OutputType([Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKey])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        $KeyRing,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
        $Id
    )

    Begin
    {
    }
    Process
    {
        [system.io.stream]$stream = [system.io.File]::OpenRead($KeyRing)
        # Decode key ring
        $instream = [Org.BouncyCastle.Bcpg.OpenPgp.PgpUtilities]::GetDecoderStream($stream)
        try
        {
            $PrivKeyBundle = New-Object -TypeName Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKeyRingBundle -ArgumentList $instream
            if (!($PrivKeyBundle))
            {
                throw "$($KeyRing) is not a valid key ring."
            }
            if ($Id)
            {
                $idlongformat = ($Id | foreach {[Convert]::ToInt64($_,16)})  -join ""
                $kp = $PrivKeyBundle.GetSecretKey($idlongformat)
                if ($kp)
                {
                    # Add some additional properties to the object
                    Add-Member -InputObject $kp -MemberType NoteProperty -Name "Id" -Value (($kp.KeyId  |  foreach { $_.ToString("X2") }) -join "")
                    #Add-Member -InputObject $kp -MemberType NoteProperty -Name "UserIds" -Value ($kp.UserIds())
                    $kp
                }
            }
            else
            {
                # Get all keyrings from the file
                foreach ($keyring in $PrivKeyBundle.GetKeyRings())
                {
                    # Get only the public keys from the key ring 
                    $kp = $keyring.GetSecretKey()
                    if ($kp)
                    {
                        if ($kp.IsSigningKey)
                        {
                            # Add some additional properties to the object
                            Add-Member -InputObject $kp -MemberType NoteProperty -Name "Id" -Value (($kp.KeyId  |  foreach { $_.ToString("X2") }) -join "")
                            #Add-Member -InputObject $kp -MemberType NoteProperty -Name "UserIds" -Value ($kp.UserIds())
                            $kp
                        }
                    }
                }
            }
        }
        catch
        {
            $error_message =  $_.Exception.Message
            if ($error_message -like "*PgpPublicKeyRing expected*")
            {
                throw "Key specified is not a public key."
            }
            elseif ($error_message -like "*unsupported version*")
            {
                throw "File specified is not a OpenPGP Key file."
            }
            else
            {
                Throw "$($error_message)"
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Get a specified or all publick keys from a OpenPGP key ring file.
.DESCRIPTION
   Get a specified or all publick keys from a OpenPGP key ring file.
.EXAMPLE
   Get-PGPPublicKey -KeyRing C:\trust.db -Id F8B506E4A1694E46


Id              : F8B506E4A1694E46
UserIds         : {The SANS Institute <sans@sans.org>, SANS NewsBites <NewsBites@sans.org>, SANS Ouch! Newsletter <SecurityAwareness@sans.org>, SANS @Risk 
                  <ConsensusSecurityVulnerabilityAlert@sans.org>}
Fingerprint     : AF19FA272F94998DFDB5DE3DF8B506E4A1694E46
Version         : 4
CreationTime    : 8/4/2000 5:33:17 PM
ValidDays       : 0
KeyId           : -525506202488451514
IsEncryptionKey : False
IsMasterKey     : True
Algorithm       : Dsa
BitStrength     : 1024
#>
function Get-PGPPublicKey
{
    [CmdletBinding()]
    [OutputType([Org.BouncyCastle.Bcpg.OpenPgp.PgpPublicKey])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        $KeyRing,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
        $Id
    )

    Begin
    {
    }
    Process
    {
        [system.io.stream]$stream = [system.io.File]::OpenRead($KeyRing)
        # Decode key ring
        $instream = [Org.BouncyCastle.Bcpg.OpenPgp.PgpUtilities]::GetDecoderStream($stream)
        try
        {
            $PubKeyBundle = New-Object -TypeName Org.BouncyCastle.Bcpg.OpenPgp.PgpPublicKeyRingBundle -ArgumentList $instream
            if (!($PubKeyBundle))
            {
                throw "$($KeyRing) is not a valid key ring."
            }
            if ($Id)
            {
                $idlongformat = ($Id | foreach {[Convert]::ToInt64($_,16)})  -join ""
                $kp = $PubKeyBundle.GetPublicKey($idlongformat)
                if ($kp)
                {
                    # Add some additional properties to the object
                    Add-Member -InputObject $kp -MemberType NoteProperty -Name "Id" -Value (($kp.KeyId  |  foreach { $_.ToString("X2") }) -join "")
                    Add-Member -InputObject $kp -MemberType NoteProperty -Name "UserIds" -Value ($kp.GetUserIds())
                    Add-Member -InputObject $kp -MemberType NoteProperty -Name "Fingerprint" -Value (($kp.GetFingerprint() |  foreach { $_.ToString("X2") }) -join "")
                    $kp
                }
            }
            else
            {
                # Get all keyrings from the file
                foreach ($keyring in $PubKeyBundle.GetKeyRings())
                {
                    # Get only the public keys from the key ring 
                    $kp = $keyring.GetPublicKey()
                    if ($kp)
                    {
                        # Add some additional properties to the object
                        Add-Member -InputObject $kp -MemberType NoteProperty -Name "Id" -Value (($kp.KeyId  |  foreach { $_.ToString("X2") }) -join "")
                        Add-Member -InputObject $kp -MemberType NoteProperty -Name "UserIds" -Value ($kp.GetUserIds())
                        Add-Member -InputObject $kp -MemberType NoteProperty -Name "Fingerprint" -Value (($kp.GetFingerprint() |  foreach { $_.ToString("X2") }) -join "")
                        $kp
                    }
                }
            }
        }
        catch
        {
            $error_message =  $_.Exception.Message
            if ($error_message -like "*PgpPublicKeyRing expected*")
            {
                throw "Key specified is not a public key."
            }
            elseif ($error_message -like "*unsupported version*")
            {
                throw "File specified is not a OpenPGP Key file."
            }
            else
            {
                Throw "$($error_message)"
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Generates a new RSA OpenPGP Key pair.
.DESCRIPTION
   Generates a new RSA OpenPGP Key pair. The keys default Size is of 2048 bits encrypted with CAST5.
   The key has a Symetric Algorithm preference of  AES 256, AES 192, AES 128, TowFish, CAST5 and 3DES.
   The key has al Asymetric Algorithum preference of SHA 256, SHA 384, SHA 512 and RipeMD160. It supports
   compression for ZLib, Zip and BZip2.
.EXAMPLE
   New-PGPRSAKeyPair -Path c:\ -Identity "Carlos Perez" -Email "carlos@infosectactico.com" -PassPhrase (Read-Host -AsSecureString) -Verbose
VERBOSE: Generating key pair.
VERBOSE: Saving secret key to C:\\95b4851b599cb231_sec.pgp
VERBOSE: Saving public key to C:\\95b4851b599cb231_pub.pgp
VERBOSE: Generating public key
#>
function New-PGPRSAKeyPair
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0,
        HelpMessage = "Path to where to save the key pair.")]
        [string]$Path,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=1,
        HelpMessage = "Identity of user of the key. (Example name of the user)")]
        [string]$Identity,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=2,
        HelpMessage = "Email address to associate key to.")]
        [string]$Email,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=3,
        HelpMessage = "Secure String representing the passphase for the key.")]
        [securestring]$PassPhrase,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [bool]$Armor = $false,

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
            "AES256")]
        [string]$SymetricAlgorithm = "CAST5",

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet(1024,2048, 3072, 4096)]
        [int]$KeySize = 2048,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [datetime]$ExpirationDate
    )

    Begin
    {
        switch ($SymetricAlgorithm)
        {
            '3DES'     {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::TripleDes}
            'CAST5'    {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Cast5}
            'BlowFish' {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Blowfish}
            'TowFish'  {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Twofish}
            'DES'      {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Des}
            'AES128'   {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Aes128}
            'AES192'   {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Aes192}
            'AES256'   {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Aes256}
            Default    {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Cast5}
        }

        if (Test-Path $Path)
        {
            $keypath = (Resolve-Path $Path).Path
        }
        else
        {
            throw "The path specified does not exist!"
        }
    }
    Process
    {
        
        $Generator = [Org.BouncyCastle.Security.GeneratorUtilities]::GetKeyPairGenerator("RSA")
        # Public exponent of 65537
        $BI = New-Object Org.BouncyCastle.Math.BigInteger -ArgumentList "10001",16
        $SecureRand =  New-Object Org.BouncyCastle.Security.SecureRandom
        $RSAOps = New-Object Org.BouncyCastle.Crypto.Parameters.RsaKeyGenerationParameters -ArgumentList $BI,$SecureRand,$KeySize,25
        $Generator.Init($RSAOps)
        $keyparams = $Generator.GenerateKeyPair()

        #hashparam
        $HashPacket = new-object Org.BouncyCastle.Bcpg.OpenPgp.PGPSignatureSubpacketGenerator
        # Prefered Symetric Algorithms in order AES 256, AES 192, AES 128, TowFish, CAST5, 3DES
        $HashPacket.setPreferredSymmetricAlgorithms($false, @(  9, 8, 7, 10, 3, 2 ));
        # Prefered Hash Algotithms in order SHA 256, SHA 384, SHA 512, RipeMD160
        $HashPacket.setPreferredHashAlgorithms($false, @(  8, 9, 10, 3 ));
        # Compression algorithums in order ZLib, Zip, BZip2
        $HashPacket.setPreferredCompressionAlgorithms($false, @( 2, 1, 3 ));
        if ($ExpirationDate)
        {
            $expirationepoch = ($ExpirationDate.ToUniversalTime() - [datetime]::UtcNow).TotalSeconds
            $HashPacket.SetKeyExpirationTime($false, $expirationepoch)
        }
        
        # Generate a key pair with default certification for use for encryption, decryption, signing and authentication
        $SignatureType = [Org.BouncyCastle.Bcpg.OpenPgp.PgpSignature]::DefaultCertification
        Write-Verbose "Generating key pair."
        $seckey = New-Object Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKey -ArgumentList $SignatureType,
            ([Org.BouncyCastle.Bcpg.PublicKeyAlgorithmTag]::RsaGeneral), 
            $keyparams.public,
            $keyparams.private,
            ([datetime]::UtcNow),
            "$($Identity) <$($email)>",
            $SymetricAlgorithm,
            ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PassPhrase))),
            $HashPacket.Generate(),
            $null,
            $SecureRand
            
        $keyID = (($seckey.KeyId | foreach { $_.ToString("X2") }) -join "")
        if ($Armor)
        {
            $SecretKey = "$($keypath)\$($keyID)_sec.asc"
            $PublicKey = "$($keypath)\$($keyID)_pub.asc"
        }
        else
        {
            $SecretKey = "$($keypath)\$($keyID)_sec.pgp"
            $PublicKey = "$($keypath)\$($keyID)_pub.pgp"
        }
        # Create IO Stream for files that will represent the keys
        $SecretStream = [System.IO.File]::Create($SecretKey)
        $PublicStream = [System.IO.File]::Create($PublicKey)

        # If ASCII Armor output is selected creted the proper object for the encoding
        if ($Armor)
        {
             $SecretStream_armor = new-object Org.BouncyCastle.Bcpg.ArmoredOutputStream $SecretStream
             $PublicStream_armor = new-object Org.BouncyCastle.Bcpg.ArmoredOutputStream $PublicStream
        }

        # Create the key pairs either in binarry or ASCII Armor
        Write-Verbose "Saving secret key to $($SecretKey)"
        Write-Verbose "Saving public key to $($PublicKey)"
        if ($Armor)
        {
            $SecKey.Encode($SecretStream_armor)
            sleep(2)
            $SecretStream_armor.close()
            $SecretStream.Close()

            Write-Verbose "Generating public key"
            $SecKey.PublicKey.encode($PublicStream_armor)
            sleep(2)
            $PublicStream_armor.close()
            $PublicStream.Close()
        }
        else
        {
            $SecKey.Encode($SecretStream)
            sleep(2)
            $SecretStream.Close()

            Write-Verbose "Generating public key"
            $SecKey.PublicKey.encode($PublicStream)
            sleep(2)
            $PublicStream.Close()
        }

    }
    End
    {
    }
}


<#
.Synopsis
   Generates a OpenPGP DSA/El Gamal key pair.
.DESCRIPTION
   Generates a new DSA/El Gamal OpenPGP Key pair. The keys default Size is of 2048 bits for El Gamal and 1024bits for DSA
   (Do to current limitations of the library used only 1024bit keys for DSA can be made)encrypted with AES-256.
   The key has a Symetric Algorithm preference of  AES 256, AES 192, AES 128, TowFish, CAST5 and 3DES.
   The key has al Asymetric Algorithum preference of SHA 256, SHA 384, SHA 512 and RipeMD160. It supports
   compression for ZLib, Zip and BZip2.
.EXAMPLE
   New-PGPDsaElGamalKeyPair -Path c:\ -Identity "Carlos Perez" -Email "gamal@tes.com" -PassPhrase (Read-Host -AsSecureString) -Verbose
VERBOSE: Generating 1024bit DSA Key.
VERBOSE: Generating 2048 El Gamal key
VERBOSE: Creating PGP key ring
VERBOSE: Generating secret key.
VERBOSE: Generating public key.
VERBOSE: Keyring has benn ceated.
VERBOSE: Saving secret key to C:\\BA7860780D86003A_sec.pgp
VERBOSE: Saving public key to C:\\BA7860780D86003A_pub.pgp

.NOTES
   General notes
#>
function New-PGPDsaElGamalKeyPair
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0,
        HelpMessage = "Path to where to save the key pair.")]
        [string]$Path,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=1,
        HelpMessage = "Identity of user of the key. (Example name of the user)")]
        [string]$Identity,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=2,
        HelpMessage = "Email address to associate key to.")]
        [string]$Email,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=3,
        HelpMessage = "Secure String representing the passphase for the key.")]
        [securestring]$PassPhrase,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [bool]$Armor = $false,

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
            "AES256")]
        [string]$SymetricAlgorithm = "AES256",

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet(1024, 2048, 3072, 4096)]
        [int]$ElGamalKeySize = 2048,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [datetime]$ExpirationDate
    )

    Begin
    {
        switch ($SymetricAlgorithm)
        {
            '3DES'     {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::TripleDes}
            'CAST5'    {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Cast5}
            'BlowFish' {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Blowfish}
            'TowFish'  {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Twofish}
            'DES'      {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Des}
            'AES128'   {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Aes128}
            'AES192'   {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Aes192}
            'AES256'   {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Aes256}
            Default    {$SymAlgo = [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag]::Aes256}
        }

        if (Test-Path $Path)
        {
            $keypath = (Resolve-Path $Path).Path
        }
        else
        {
            throw "The path specified does not exist!"
        }
    }
    Process
    {
        
        # Gnerate DSA Key
        ########################
        $SecureRand =  New-Object Org.BouncyCastle.Security.SecureRandom
        $DSAGenerator = [Org.BouncyCastle.Security.GeneratorUtilities]::GetKeyPairGenerator("DSA")
        $pgen = New-Object Org.BouncyCastle.Crypto.Generators.DsaParametersGenerator
        $pgen.Init(1024,80,$SecureRand)
        $DSAParameters = $pgen.GenerateParameters()
        $DSAOps = New-Object Org.BouncyCastle.Crypto.Parameters.DsaKeyGenerationParameters -ArgumentList $SecureRand,$DSAParameters
        $DSAGenerator.Init($DSAOps)
        # The library limits DSA creation to 1024
        Write-Verbose "Generating 1024bit DSA Key."
        $DSAKeyPair = $DSAGenerator.GenerateKeyPair()

        # Generate El Gamal key
        #########################
        $SecureRandEG =  New-Object Org.BouncyCastle.Security.SecureRandom
        $ElGamalGenerator = [Org.BouncyCastle.Security.GeneratorUtilities]::GetKeyPairGenerator("ELGAMAL")
        $EGPrime = Get-MODP -BitSize $ElGamalKeySize
        $EGBaseGenerator = New-Object Org.BouncyCastle.Math.BigInteger -ArgumentList "2",16
        $ElGamalParameterSet = New-Object Org.BouncyCastle.Crypto.Parameters.ElGamalParameters -ArgumentList $EGPrime,$EGBaseGenerator
        $ELGKP = New-Object Org.BouncyCastle.Crypto.Parameters.ElGamalKeyGenerationParameters -ArgumentList $SecureRandEG, $ElGamalParameterSet
        $ElGamalGenerator.Init($ELGKP)
        Write-Verbose "Generating $($ElGamalKeySize) El Gamal key"
        $ElGamalKeyPair = $ElGamalGenerator.GenerateKeyPair()


        # Create parameters for Hashed packets
        $HashPacket = new-object Org.BouncyCastle.Bcpg.OpenPgp.PGPSignatureSubpacketGenerator
        # Prefered Symetric Algorithms in order AES 256, AES 192, AES 128, TowFish, CAST5, 3DES
        $HashPacket.setPreferredSymmetricAlgorithms($false, @(  9, 8, 7, 10, 3, 2 ));
        # Prefered Hash Algotithms in order SHA 256, SHA 384, SHA 512, RipeMD160
        $HashPacket.setPreferredHashAlgorithms($false, @(  8, 9, 10, 3 ));
        # Compression algorithums in order ZLib, Zip, BZip2
        $HashPacket.setPreferredCompressionAlgorithms($false, @( 2, 1, 3 ));
        if ($ExpirationDate)
        {
            $expirationepoch = ($ExpirationDate.ToUniversalTime() - [datetime]::UtcNow).TotalSeconds
            $HashPacket.SetKeyExpirationTime($false, $expirationepoch)
        }
        
        Write-Verbose "Creating PGP key ring"
        $PGPDSAPair = New-Object Org.BouncyCastle.Bcpg.OpenPgp.PgpKeyPair -ArgumentList ([Org.BouncyCastle.Bcpg.PublicKeyAlgorithmTag]::Dsa),
                        $DSAKeyPair,
                        ([datetime]::UtcNow)

        $PGPEGPair = New-Object Org.BouncyCastle.Bcpg.OpenPgp.PgpKeyPair -ArgumentList ([Org.BouncyCastle.Bcpg.PublicKeyAlgorithmTag]::ElGamalEncrypt),
                        $ElGamalKeyPair,
                        ([datetime]::UtcNow)
        
        # Generate a key pair with default certification for use for encryption, decryption, signing and authentication
        $SignatureType = [Org.BouncyCastle.Bcpg.OpenPgp.PgpSignature]::DefaultCertification
        $KeyringGen = New-Object Org.BouncyCastle.Bcpg.OpenPgp.PgpKeyRingGenerator -ArgumentList $SignatureType, 
                   $PGPDSAPair,
                   "$($Identity) <$($email)>",
                   $SymAlgo,
                   ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PassPhrase))),
                   $true,
                   $null,
                   $null,
                   $SecureRand

        $KeyringGen.AddSubKey($PGPEGPair)
        Write-Verbose "Generating secret key."
        $seckey = $keyRingGen.GenerateSecretKeyRing()
        Write-Verbose "Generating public key."
        $pubkey = $keyRingGen.GeneratePublicKeyRing()
        Write-Verbose "Keyring has benn ceated."
        $keyID = (($seckey.GetSecretKey().keyID | foreach { $_.ToString("X2") }) -join "")
        if ($Armor)
        {
            $SecretKey = "$($keypath)\$($keyID)_sec.asc"
            $PublicKey = "$($keypath)\$($keyID)_pub.asc"
        }
        else
        {
            $SecretKey = "$($keypath)\$($keyID)_sec.pgp"
            $PublicKey = "$($keypath)\$($keyID)_pub.pgp"
        }
        # Create IO Stream for files that will represent the keys
        $SecretStream = [System.IO.File]::Create($SecretKey)
        $PublicStream = [System.IO.File]::Create($PublicKey)

        # If ASCII Armor output is selected creted the proper object for the encoding
        if ($Armor)
        {
             $SecretStream_armor = new-object Org.BouncyCastle.Bcpg.ArmoredOutputStream $SecretStream
             $PublicStream_armor = new-object Org.BouncyCastle.Bcpg.ArmoredOutputStream $PublicStream
        }

        # Create the key pairs either in binarry or ASCII Armor
        Write-Verbose "Saving secret key to $($SecretKey)"
        Write-Verbose "Saving public key to $($PublicKey)"
        if ($Armor)
        {
            $SecKey.Encode($SecretStream_armor)
            sleep(2)
            $SecretStream_armor.close()
            $SecretStream.Close()

            $pubkey.encode($PublicStream_armor)
            sleep(2)
            $PublicStream_armor.close()
            $PublicStream.Close()
        }
        else
        {
            $SecKey.Encode($SecretStream)
            sleep(2)
            $SecretStream.Close()

            $pubkey.encode($PublicStream)
            sleep(2)
            $PublicStream.Close()
        }

    }
    End
    {
    }
}

<#
.Synopsis
   Get More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)
.DESCRIPTION
   Get More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE). 
   Based on http://www.ietf.org/rfc/rfc3526.txt
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-MODP
{
    [CmdletBinding()]
    [OutputType([Org.BouncyCastle.Math.BigInteger])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                Position=0)]
        [ValidateSet(1536,2048,3072,4096)]   
        $BitSize
    )

    Begin
    {
        #$sb = [System.Text.StringBuilder]""
    }
    Process
    {
        switch ($BitSize)
        {
         
            4096 {
                $sbs = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
                "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
                "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"+
                "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"+
                "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"+
                "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"+
                "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"+
                "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"+
                "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"+
                "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"+
                "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"+
                "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"+
                "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"+
                "FFFFFFFFFFFFFFFF"
                return New-Object Org.BouncyCastle.Math.BigInteger -ArgumentList $sbs,16
            }

            3072 {
                $sbs = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
                "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
                "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"+
                "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"+
                "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"+
                "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"+
                "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"+
                "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
                return New-Object Org.BouncyCastle.Math.BigInteger -ArgumentList $sbs,16
            }

            2048 {
                $sbs = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
                "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
                "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
                 New-Object Org.BouncyCastle.Math.BigInteger -ArgumentList $sbs,16
            }

            1536 {
                $sbs = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
                "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
                return New-Object Org.BouncyCastle.Math.BigInteger -ArgumentList $sbs,16
            }
        }
    }
    End
    {
    }
}