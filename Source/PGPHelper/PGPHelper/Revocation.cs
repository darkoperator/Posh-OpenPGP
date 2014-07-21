using System;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;

namespace PGPHelper
{
    public sealed class Revocation
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="SecretKey"></param>
        /// <param name="Passhrase"></param>
        /// <param name="Reason"></param>
        /// <param name="RevokeDescription"></param>
        /// <param name="OutFile"></param>
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
            var subHashGenerator = new PgpSignatureSubpacketGenerator();
            var subUnHashGenerator = new PgpSignatureSubpacketGenerator();

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
            var generator = new PgpSignatureGenerator(SecretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.KeyRevocation, privKey, new SecureRandom());

            // Create the hashed and unhashed subpackets and add them to the signature generator.
            subHashGenerator.SetSignatureCreationTime(false, DateTime.UtcNow);
            subHashGenerator.SetRevocationReason(false, RevokeReason, RevokeDescription);
            subUnHashGenerator.SetRevocationKey(false, SecretKey.PublicKey.Algorithm, SecretKey.PublicKey.GetFingerprint());
            generator.SetHashedSubpackets(subHashGenerator.Generate());
            generator.SetUnhashedSubpackets(subUnHashGenerator.Generate());

            // Generate the certification
            var signature = generator.GenerateCertification(SecretKey.PublicKey);

            // Create the armour output stream and set the headers
            var mStream = new MemoryStream();
            using (var outAStream = new ArmoredOutputStream(mStream))
            {
                outAStream.SetHeader("Version", "Posh-OpenPGP");
                outAStream.SetHeader("Comment", "A revocation certificate should follow");
                signature.Encode(outAStream);
                outAStream.Close();
            }

            // Turn the stream in to armour text and make sure we replace the propper headers
            mStream.Position = 0;
            var sr = new StreamReader(mStream);
            var armour = sr.ReadToEnd();
            var outstr = armour.Replace("BEGIN PGP SIGNATURE", "BEGIN PGP PUBLIC KEY BLOCK").Replace("END PGP SIGNATURE", "END PGP PUBLIC KEY BLOCK");

            // Save the string to the specified file.
            System.IO.File.WriteAllText(OutFile, outstr);
        }

        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="SecretKey"></param>
        /// <param name="Passhrase"></param>
        /// <param name="Reason"></param>
        /// <param name="RevokeDescription"></param>
        /// <returns></returns>
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
            var subHashGenerator = new PgpSignatureSubpacketGenerator();
            var subUnHashGenerator = new PgpSignatureSubpacketGenerator();

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
            var generator = new PgpSignatureGenerator(SecretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.KeyRevocation, privKey, new SecureRandom());

            // Create the hashed and unhashed subpackets and add them to the signature generator.
            subHashGenerator.SetSignatureCreationTime(false, DateTime.UtcNow);
            subHashGenerator.SetRevocationReason(false, RevokeReason, RevokeDescription);
            subUnHashGenerator.SetRevocationKey(false, SecretKey.PublicKey.Algorithm, SecretKey.PublicKey.GetFingerprint());
            generator.SetHashedSubpackets(subHashGenerator.Generate());
            generator.SetUnhashedSubpackets(subUnHashGenerator.Generate());

            // Generate the certification
            var signature = generator.GenerateCertification(SecretKey.PublicKey);

            // Create the armour output stream and set the headers
            var mStream = new MemoryStream();
            using (var outAStream = new ArmoredOutputStream(mStream))
            {
                outAStream.SetHeader("Version", "Posh-OpenPGP");
                outAStream.SetHeader("Comment", "A revocation certificate should follow");
                signature.Encode(outAStream);
                outAStream.Close();
            }

            // Turn the stream in to armour text and make sure we replace the propper headers
            mStream.Position = 0;
            var sr = new StreamReader(mStream);
            var armour = sr.ReadToEnd();
            var outstr = armour.Replace("BEGIN PGP SIGNATURE", "BEGIN PGP PUBLIC KEY BLOCK").Replace("END PGP SIGNATURE", "END PGP PUBLIC KEY BLOCK");

            return outstr;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="SecretKey"></param>
        /// <param name="Passhrase"></param>
        /// <param name="Reason"></param>
        /// <param name="RevokeDescription"></param>
        /// <returns></returns>
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
            var subHashGenerator = new PgpSignatureSubpacketGenerator();
            var subUnHashGenerator = new PgpSignatureSubpacketGenerator();

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
            var generator = new PgpSignatureGenerator(SecretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.KeyRevocation, privKey, new SecureRandom());

            // Create the hashed and unhashed subpackets and add them to the signature generator.
            subHashGenerator.SetSignatureCreationTime(false, DateTime.UtcNow);
            subHashGenerator.SetRevocationReason(false, RevokeReason, RevokeDescription);
            subUnHashGenerator.SetRevocationKey(false, SecretKey.PublicKey.Algorithm, SecretKey.PublicKey.GetFingerprint());
            generator.SetHashedSubpackets(subHashGenerator.Generate());
            generator.SetUnhashedSubpackets(subUnHashGenerator.Generate());

            // Generate the certification
            var signature = generator.GenerateCertification(SecretKey.PublicKey);

            return signature;
        }
    }
}
