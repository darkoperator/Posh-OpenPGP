using System;
using System.Collections;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

namespace PGPHelper
{
    public sealed class Revocation
    {
        public static void GenerateCertificate(PgpSecretKey SecretKey, char[] Passhrase, string Reason, string RevokeDescription, string OutFile)
        {
            RevocationReasonTag RevokeReason;
            if (string.Equals(Reason, "Compromised", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.KeyCompromised;
            }
            else if (string.Equals(Reason, "Retired", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.KeyRetired;
            }
            else if (string.Equals(Reason, "Superseded", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.KeySuperseded;
            }
            else if (string.Equals(Reason, "NoReason", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.NoReason;
            }
            else if (string.Equals(Reason, "Invalid", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.UserNoLongerValid;
            }
            else
            {
                RevokeReason = RevocationReasonTag.NoReason;
            }

            // Create the subpacket generators for the hashed and unhashed packets.
            PgpSignatureSubpacketGenerator subHashGenerator = new PgpSignatureSubpacketGenerator();
            PgpSignatureSubpacketGenerator subUnHashGenerator = new PgpSignatureSubpacketGenerator();

            // Extract the private key from the secret key.
            PgpPrivateKey privKey;
            try
            {
                privKey = SecretKey.ExtractPrivateKey(Passhrase);
            }
            catch
            {
                throw new PgpException("Wrong Passphrase, could not extract private key.");
            }

            // Create a signature generator and initialize it for key revocation.
            PgpSignatureGenerator generator = new PgpSignatureGenerator(SecretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.KeyRevocation, privKey, new SecureRandom());

            // Create the hashed and unhashed subpackets and add them to the signature generator.
            subHashGenerator.SetSignatureCreationTime(false, DateTime.UtcNow);
            subHashGenerator.SetRevocationReason(false, RevokeReason, RevokeDescription);
            subUnHashGenerator.SetRevocationKey(false, SecretKey.PublicKey.Algorithm, SecretKey.PublicKey.GetFingerprint());
            generator.SetHashedSubpackets(subHashGenerator.Generate());
            generator.SetUnhashedSubpackets(subUnHashGenerator.Generate());

            // Generate the certification
            PgpSignature signature = generator.GenerateCertification(SecretKey.PublicKey);

            // Create the armour output stream and set the headers
            MemoryStream mStream = new MemoryStream();
            using (ArmoredOutputStream outAStream = new ArmoredOutputStream(mStream))
            {
                outAStream.SetHeader("Version", "Posh-OpenPGP");
                outAStream.SetHeader("Comment", "A revocation certificate should follow");
                signature.Encode(outAStream);
                outAStream.Close();
            }

            // Turn the stream in to armour text and make sure we replace the propper headers
            mStream.Position = 0;
            var sr = new StreamReader(mStream);
            string armour = sr.ReadToEnd();
            string outstr = armour.Replace("BEGIN PGP SIGNATURE", "BEGIN PGP PUBLIC KEY BLOCK").Replace("END PGP SIGNATURE", "END PGP PUBLIC KEY BLOCK");

            // Save the string to the specified file.
            System.IO.File.WriteAllText(OutFile, outstr);
        }

        
        public static string GenerateCertificate(PgpSecretKey SecretKey, char[] Passhrase, string Reason, string RevokeDescription)
        {
            RevocationReasonTag RevokeReason;
            if (string.Equals(Reason, "Compromised", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.KeyCompromised;
            }
            else if (string.Equals(Reason, "Retired", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.KeyRetired;
            }
            else if (string.Equals(Reason, "Superseded", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.KeySuperseded;
            }
            else if (string.Equals(Reason, "NoReason", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.NoReason;
            }
            else if (string.Equals(Reason, "Invalid", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.UserNoLongerValid;
            }
            else
            {
                RevokeReason = RevocationReasonTag.NoReason;
            }

            // Create the subpacket generators for the hashed and unhashed packets.
            PgpSignatureSubpacketGenerator subHashGenerator = new PgpSignatureSubpacketGenerator();
            PgpSignatureSubpacketGenerator subUnHashGenerator = new PgpSignatureSubpacketGenerator();

            // Extract the private key from the secret key.
            PgpPrivateKey privKey;
            try
            {
                privKey = SecretKey.ExtractPrivateKey(Passhrase);
            }
            catch
            {
                throw new PgpException("Wrong Passphrase, could not extract private key.");
            }

            // Create a signature generator and initialize it for key revocation.
            PgpSignatureGenerator generator = new PgpSignatureGenerator(SecretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.KeyRevocation, privKey, new SecureRandom());

            // Create the hashed and unhashed subpackets and add them to the signature generator.
            subHashGenerator.SetSignatureCreationTime(false, DateTime.UtcNow);
            subHashGenerator.SetRevocationReason(false, RevokeReason, RevokeDescription);
            subUnHashGenerator.SetRevocationKey(false, SecretKey.PublicKey.Algorithm, SecretKey.PublicKey.GetFingerprint());
            generator.SetHashedSubpackets(subHashGenerator.Generate());
            generator.SetUnhashedSubpackets(subUnHashGenerator.Generate());

            // Generate the certification
            PgpSignature signature = generator.GenerateCertification(SecretKey.PublicKey);

            // Create the armour output stream and set the headers
            MemoryStream mStream = new MemoryStream();
            using (ArmoredOutputStream outAStream = new ArmoredOutputStream(mStream))
            {
                outAStream.SetHeader("Version", "Posh-OpenPGP");
                outAStream.SetHeader("Comment", "A revocation certificate should follow");
                signature.Encode(outAStream);
                outAStream.Close();
            }

            // Turn the stream in to armour text and make sure we replace the propper headers
            mStream.Position = 0;
            var sr = new StreamReader(mStream);
            string armour = sr.ReadToEnd();
            string outstr = armour.Replace("BEGIN PGP SIGNATURE", "BEGIN PGP PUBLIC KEY BLOCK").Replace("END PGP SIGNATURE", "END PGP PUBLIC KEY BLOCK");

            return outstr;
        }


        public static PgpSignature GenerateSignature(PgpSecretKey SecretKey, char[] Passhrase, string Reason, string RevokeDescription)
        {
            RevocationReasonTag RevokeReason;
            if (string.Equals(Reason, "Compromised", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.KeyCompromised;
            }
            else if (string.Equals(Reason, "Retired", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.KeyRetired;
            }
            else if (string.Equals(Reason, "Superseded", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.KeySuperseded;
            }
            else if (string.Equals(Reason, "NoReason", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.NoReason;
            }
            else if (string.Equals(Reason, "Invalid", StringComparison.CurrentCultureIgnoreCase))
            {
                RevokeReason = RevocationReasonTag.UserNoLongerValid;
            }
            else
            {
                RevokeReason = RevocationReasonTag.NoReason;
            }

            // Create the subpacket generators for the hashed and unhashed packets.
            PgpSignatureSubpacketGenerator subHashGenerator = new PgpSignatureSubpacketGenerator();
            PgpSignatureSubpacketGenerator subUnHashGenerator = new PgpSignatureSubpacketGenerator();

            // Extract the private key from the secret key.
            PgpPrivateKey privKey;
            try
            {
                privKey = SecretKey.ExtractPrivateKey(Passhrase);
            }
            catch
            {
                throw new PgpException("Wrong Passphrase, could not extract private key.");
            }

            // Create a signature generator and initialize it for key revocation.
            PgpSignatureGenerator generator = new PgpSignatureGenerator(SecretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.KeyRevocation, privKey, new SecureRandom());

            // Create the hashed and unhashed subpackets and add them to the signature generator.
            subHashGenerator.SetSignatureCreationTime(false, DateTime.UtcNow);
            subHashGenerator.SetRevocationReason(false, RevokeReason, RevokeDescription);
            subUnHashGenerator.SetRevocationKey(false, SecretKey.PublicKey.Algorithm, SecretKey.PublicKey.GetFingerprint());
            generator.SetHashedSubpackets(subHashGenerator.Generate());
            generator.SetUnhashedSubpackets(subUnHashGenerator.Generate());

            // Generate the certification
            PgpSignature signature = generator.GenerateCertification(SecretKey.PublicKey);

            return signature;
        }
    }
}
