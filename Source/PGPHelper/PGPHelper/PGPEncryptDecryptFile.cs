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
    public class PGPEncryptDecrypt
    {

        public static void DecryptFile(Stream inputStream, PgpSecretKey pgpSecKey, char[] passwd, string pathToSaveFile)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
            PgpEncryptedDataList enc;
            PgpObject o = pgpF.NextPgpObject();

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

            Stream clear = pbe.GetDataStream(sKey);
            PgpObjectFactory plainFact = new PgpObjectFactory(clear);
            PgpObject message = plainFact.NextPgpObject();

            if (message is PgpCompressedData)
            {
                PgpCompressedData cData = (PgpCompressedData)message;
                PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());
                message = pgpFact.NextPgpObject();
            }

            if (message is PgpLiteralData)
            {

                PgpLiteralData ld = (PgpLiteralData)message;
                Stream fOut = File.Create(pathToSaveFile);
                Stream unc = ld.GetInputStream();
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


        public static void EncryptFile(Stream outputStream, string fileName, PgpPublicKey[] encKeys, bool armor, bool withIntegrityCheck, string compressionName, string symmAlgorithm)
        {
            if (armor)
            {
                ArmoredOutputStream aOutStream = new ArmoredOutputStream(outputStream);
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

            MemoryStream bOut = new MemoryStream();
            PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(
            comptype);
            PgpUtilities.WriteFileToLiteralData(
                comData.Open(bOut),
                PgpLiteralData.Binary,
                new FileInfo(fileName));
            comData.Close();
            PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(
            symtype, withIntegrityCheck, new SecureRandom());
            foreach (PgpPublicKey encKey in encKeys)
            {
                cPk.AddMethod(encKey);
            }
            byte[] bytes = bOut.ToArray();
            Stream cOut = cPk.Open(outputStream, bytes.Length);
            cOut.Write(bytes, 0, bytes.Length);
            cOut.Close();
            if (armor)
            {
                outputStream.Close();
            }

        }

        
        // Based on http://jopinblog.wordpress.com/2008/06/23/pgp-single-pass-sign-and-encrypt-with-bouncy-castle/

        public static void SignAndEncryptFile(string actualFileName,
               string embeddedFileName,
               PgpSecretKey pgpSecKey,
               string OutputFileName,
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
            const int BUFFER_SIZE = 1 << 16; // should always be power of 2
            Stream outputStream = File.Open(OutputFileName, FileMode.Create);

            if (armor)
            {
                ArmoredOutputStream aOutStream = new ArmoredOutputStream(outputStream);
                aOutStream.SetHeader("Version", "Posh-OpenPGP");
                outputStream = aOutStream;
            }

            // Init encrypted data generator
            PgpEncryptedDataGenerator encryptedDataGenerator =
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());

            // add keys to encrypt to
            foreach (PgpPublicKey encKey in encKeys)
                encryptedDataGenerator.AddMethod(encKey);
            Stream encryptedOut = encryptedDataGenerator.Open(outputStream, new byte[BUFFER_SIZE]);

            // Init compression
            PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(comptype);
            Stream compressedOut = compressedDataGenerator.Open(encryptedOut);

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
            PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, digest);
            signatureGenerator.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);

            foreach (string userId in pgpSecKey.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator();
                spGen.SetSignerUserId(false, userId);
                signatureGenerator.SetHashedSubpackets(spGen.Generate());

                // Just the first one!
                break;

            }
            signatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);

            // Create the Literal Data generator output stream
            PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
            FileInfo embeddedFile = new FileInfo(embeddedFileName);
            FileInfo actualFile = new FileInfo(actualFileName);

            Stream literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Binary,
                embeddedFile.Name, DateTime.UtcNow, new byte[BUFFER_SIZE]);

            // Open the input file
            FileStream inputStream = actualFile.OpenRead();
            byte[] buf = new byte[BUFFER_SIZE];
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
