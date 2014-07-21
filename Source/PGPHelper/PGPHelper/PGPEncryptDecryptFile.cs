using System;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace PGPHelper
{
    public class PgpEncryptDecrypt
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputStream"></param>
        /// <param name="pgpSecKey"></param>
        /// <param name="passwd"></param>
        /// <param name="pathToSaveFile"></param>
        public static void DecryptFile(
            Stream inputStream, 
            PgpSecretKey pgpSecKey, 
            char[] passwd, 
            string pathToSaveFile)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            var pgpF = new PgpObjectFactory(inputStream);
            PgpEncryptedDataList enc;
            var o = pgpF.NextPgpObject();

            //
            // the first object might be a PGP marker packet.
            //

            if (o is PgpEncryptedDataList)
            {
                enc = (PgpEncryptedDataList)o;
            }

            else
            {
                enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
            }

            //
            // find the secret key
            //

            PgpPrivateKey sKey = null;
            PgpPublicKeyEncryptedData pbe = null;


            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            {
                sKey = pgpSecKey.ExtractPrivateKey(passwd);

                if (sKey != null)
                {
                    pbe = pked;
                    break;
                }
            }

            if (sKey == null)
            {
                throw new ArgumentException("secret key for message not found.");
            }

            var clear = pbe.GetDataStream(sKey);
            var plainFact = new PgpObjectFactory(clear);
            var message = plainFact.NextPgpObject();

            if (message is PgpCompressedData)
            {
                var cData = (PgpCompressedData)message;
                var pgpFact = new PgpObjectFactory(cData.GetDataStream());
                message = pgpFact.NextPgpObject();
            }

            if (message is PgpLiteralData)
            {

                var ld = (PgpLiteralData)message;
                Stream fOut = File.Create(pathToSaveFile);
                var unc = ld.GetInputStream();
                Streams.PipeAll(unc, fOut);
                fOut.Close();

            }

            else if (message is PgpOnePassSignatureList)
            {
                throw new PgpException("encrypted message contains a signed message - not literal data.");
            }

            else
            {
                throw new PgpException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.IsIntegrityProtected())
            {

                if (!pbe.Verify())
                {
                    throw new PgpException("message failed integrity check");
                }
            }

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="outputStream"></param>
        /// <param name="fileName"></param>
        /// <param name="encKeys"></param>
        /// <param name="armor"></param>
        /// <param name="withIntegrityCheck"></param>
        /// <param name="compressionName"></param>
        /// <param name="symmAlgorithm"></param>
        public static void EncryptFile(
            Stream outputStream, 
            string fileName, 
            PgpPublicKey[] encKeys, 
            bool armor, 
            bool withIntegrityCheck, 
            string compressionName, 
            string symmAlgorithm)
        {
            if (armor)
            {
                var aOutStream = new ArmoredOutputStream(outputStream);
                aOutStream.SetHeader("Version", "Posh-OpenPGP");
                outputStream = aOutStream;
            }

            CompressionAlgorithmTag comptype;

            if (string.Equals(compressionName, "Uncompressed", StringComparison.CurrentCultureIgnoreCase))
            {
                comptype = CompressionAlgorithmTag.Uncompressed;
            }
            else if (string.Equals(compressionName, "Zip", StringComparison.CurrentCultureIgnoreCase))
            {
                comptype = CompressionAlgorithmTag.Zip;
            }
            else if (string.Equals(compressionName, "Zlib", StringComparison.CurrentCultureIgnoreCase))
            {
                comptype = CompressionAlgorithmTag.ZLib;
            }
            else if (string.Equals(compressionName, "BZip2", StringComparison.CurrentCultureIgnoreCase))
            {
                comptype = CompressionAlgorithmTag.BZip2;
            }
            else
            {
                comptype = CompressionAlgorithmTag.Zip;
            }

            SymmetricKeyAlgorithmTag symtype;

            if (string.Equals(symmAlgorithm, "Aes256", StringComparison.CurrentCultureIgnoreCase))
            {
                symtype = SymmetricKeyAlgorithmTag.Aes256;
            }
            else if (string.Equals(symmAlgorithm, "Aes192", StringComparison.CurrentCultureIgnoreCase))
            {
                symtype = SymmetricKeyAlgorithmTag.Aes192;
            }
            else if (string.Equals(symmAlgorithm, "Aes128", StringComparison.CurrentCultureIgnoreCase))
            {
                symtype = SymmetricKeyAlgorithmTag.Aes128;
            }
            else if (string.Equals(symmAlgorithm, "Blowfish", StringComparison.CurrentCultureIgnoreCase))
            {
                symtype = SymmetricKeyAlgorithmTag.Blowfish;
            }
            else if (string.Equals(symmAlgorithm, "Twofish", StringComparison.CurrentCultureIgnoreCase))
            {
                symtype = SymmetricKeyAlgorithmTag.Twofish;
            }
            else if (string.Equals(symmAlgorithm, "Cast5", StringComparison.CurrentCultureIgnoreCase))
            {
                symtype = SymmetricKeyAlgorithmTag.Cast5;
            }
            else if (string.Equals(symmAlgorithm, "Idea", StringComparison.CurrentCultureIgnoreCase))
            {
                symtype = SymmetricKeyAlgorithmTag.Idea;
            }
            else if (string.Equals(symmAlgorithm, "DES", StringComparison.CurrentCultureIgnoreCase))
            {
                symtype = SymmetricKeyAlgorithmTag.Des;
            }
            else if (string.Equals(symmAlgorithm, "3DES", StringComparison.CurrentCultureIgnoreCase))
            {
                symtype = SymmetricKeyAlgorithmTag.TripleDes;
            }
            else
            {
                symtype = SymmetricKeyAlgorithmTag.Twofish;
            }

            var bOut = new MemoryStream();
            var comData = new PgpCompressedDataGenerator(
            comptype);
            PgpUtilities.WriteFileToLiteralData(
                comData.Open(bOut),
                PgpLiteralData.Binary,
                new FileInfo(fileName));

            comData.Close();
            
            var cPk = new PgpEncryptedDataGenerator(
                                                    symtype, withIntegrityCheck, 
                                                    new SecureRandom());
            foreach (var encKey in encKeys)
            {
                cPk.AddMethod(encKey);
            }
            var bytes = bOut.ToArray();
            var cOut = cPk.Open(outputStream, bytes.Length);
            cOut.Write(bytes, 0, bytes.Length);
            cOut.Close();
            if (armor)
            {
                outputStream.Close();
            }

        }

        
        // Based on http://jopinblog.wordpress.com/2008/06/23/pgp-single-pass-sign-and-encrypt-with-bouncy-castle/
        /// <summary>
        /// 
        /// </summary>
        /// <param name="actualFileName"></param>
        /// <param name="embeddedFileName"></param>
        /// <param name="pgpSecKey"></param>
        /// <param name="outputFileName"></param>
        /// <param name="password"></param>
        /// <param name="armor"></param>
        /// <param name="withIntegrityCheck"></param>
        /// <param name="encKeys"></param>
        /// <param name="compressionName"></param>
        /// <param name="digestName"></param>
        public static void SignAndEncryptFile(string actualFileName,
               string embeddedFileName,
               PgpSecretKey pgpSecKey,
               string outputFileName,
               char[] password,
               bool armor,
               bool withIntegrityCheck,
               PgpPublicKey[] encKeys,
               string compressionName,
               string digestName)
        {

            CompressionAlgorithmTag comptype;

            if (string.Equals(compressionName, "Uncompressed", StringComparison.CurrentCultureIgnoreCase))
            {
                comptype = CompressionAlgorithmTag.Uncompressed;
            }
            else if (string.Equals(compressionName, "Zip", StringComparison.CurrentCultureIgnoreCase))
            {
                comptype = CompressionAlgorithmTag.Zip;
            }
            else if (string.Equals(compressionName, "Zlib", StringComparison.CurrentCultureIgnoreCase))
            {
                comptype = CompressionAlgorithmTag.ZLib;
            }
            else if (string.Equals(compressionName, "BZip2", StringComparison.CurrentCultureIgnoreCase))
            {
                comptype = CompressionAlgorithmTag.BZip2;
            }
            else
            {
                comptype = CompressionAlgorithmTag.Zip;
            }

            HashAlgorithmTag digest;

            if (string.Equals(digestName, "Sha256", StringComparison.CurrentCultureIgnoreCase))
            {
                digest = HashAlgorithmTag.Sha256;
            }
            else if (string.Equals(digestName, "Sha384", StringComparison.CurrentCultureIgnoreCase))
            {
                digest = HashAlgorithmTag.Sha384;
            }
            else if (string.Equals(digestName, "Sha512", StringComparison.CurrentCultureIgnoreCase))
            {
                digest = HashAlgorithmTag.Sha512;
            }
            else if (string.Equals(digestName, "MD5", StringComparison.CurrentCultureIgnoreCase))
            {
                digest = HashAlgorithmTag.MD5;
            }
            else if (string.Equals(digestName, "RipeMD160", StringComparison.CurrentCultureIgnoreCase))
            {
                digest = HashAlgorithmTag.RipeMD160;
            }
            else
            {
                digest = HashAlgorithmTag.Sha512;
            }
            const int bufferSize = 1 << 16; // should always be power of 2
            Stream outputStream = File.Open(outputFileName, FileMode.Create);

            if (armor)
            {
                var aOutStream = new ArmoredOutputStream(outputStream);
                aOutStream.SetHeader("Version", "Posh-OpenPGP");
                outputStream = aOutStream;
            }

            // Init encrypted data generator
            var encryptedDataGenerator =
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());

            // add keys to encrypt to
            foreach (var encKey in encKeys)
                encryptedDataGenerator.AddMethod(encKey);
            var encryptedOut = encryptedDataGenerator.Open(outputStream, new byte[bufferSize]);

            // Init compression
            var compressedDataGenerator = new PgpCompressedDataGenerator(comptype);
            var compressedOut = compressedDataGenerator.Open(encryptedOut);

            // Init signature
            PgpPrivateKey pgpPrivKey;
            try
            {
                pgpPrivKey = pgpSecKey.ExtractPrivateKey(password);
            }
            catch
            {
                throw new PgpException("Wrong Passphrase, could not extract private key.");
            }
            var signatureGenerator = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, digest);
            signatureGenerator.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);

            foreach (string userId in pgpSecKey.PublicKey.GetUserIds())
            {
                var spGen = new PgpSignatureSubpacketGenerator();
                spGen.SetSignerUserId(false, userId);
                signatureGenerator.SetHashedSubpackets(spGen.Generate());

                // Just the first one!
                break;

            }
            signatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);

            // Create the Literal Data generator output stream
            var literalDataGenerator = new PgpLiteralDataGenerator();
            var embeddedFile = new FileInfo(embeddedFileName);
            var actualFile = new FileInfo(actualFileName);

            var literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Binary,
                embeddedFile.Name, DateTime.UtcNow, new byte[bufferSize]);

            // Open the input file
            var inputStream = actualFile.OpenRead();
            var buf = new byte[bufferSize];
            int len;
            while ((len = inputStream.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, len);
                signatureGenerator.Update(buf, 0, len);
            }

            literalOut.Close();
            literalDataGenerator.Close();
            signatureGenerator.Generate().Encode(compressedOut);
            compressedOut.Close();
            compressedDataGenerator.Close();
            encryptedOut.Close();
            encryptedDataGenerator.Close();
            inputStream.Close();
            if (armor)
                outputStream.Close();
        }

    }
}
