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
    public static class KeyUtilities
    {
        internal static byte[] CompressFile(string fileName, CompressionAlgorithmTag algorithm)
        {
            MemoryStream bOut = new MemoryStream();
            PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(algorithm);
            PgpUtilities.WriteFileToLiteralData(comData.Open(bOut), PgpLiteralData.Binary,
                new FileInfo(fileName));
            comData.Close();
            return bOut.ToArray();
        }

        /**
         * Search a secret key ring collection for a secret key corresponding to keyID if it
         * exists.
         * 
         * @param pgpSec a secret key ring collection.
         * @param keyID keyID we want.
         * @param pass passphrase to decrypt secret key with.
         * @return
         * @throws PGPException
         * @throws NoSuchProviderException
         */
        public static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyID, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyID);

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        public static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, string UserID, char[] pass)
        {
            
            foreach (PgpSecretKeyRing keyRing in pgpSec.GetKeyRings(UserID, true, true))
            {
                foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                {
                    if (key.IsSigningKey)
                    {
                        return key.ExtractPrivateKey(pass);
                    }
                }
            }
            return null;
        }

        public static PgpPublicKey FindPublicKey(PgpPublicKeyRingBundle pgpPub, long keyID, char[] pass)
        {
            PgpPublicKey pgpPubKey = pgpPub.GetPublicKey(keyID);

            if (pgpPubKey == null)
            {
                return null;
            }

            return pgpPubKey;
        }

        public static PgpPublicKey[] FindPublicKey(PgpPublicKeyRingBundle pgpPub, string UserID, char[] pass)
        {
            PgpPublicKey[] Keys = new PgpPublicKey[50];
            int Index = 0;
            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings(UserID, true, true))
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    
                    Keys[Index] = key;
                    Index++;
                }
            }
            if (Keys.Length > 0)
            {
                return Keys;
            }
            else
            {
                return null;
            }
        }

        public static PgpPublicKeyRingBundle ReadPublicKeBundle(string fileName)
        {
            using (Stream keyIn = File.OpenRead(fileName))
            {
                PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(
                PgpUtilities.GetDecoderStream(keyIn));

                return pgpPub;
            }
        }

        public static PgpPublicKey ReadPublicKey(string fileName)
        {
            using (Stream keyIn = File.OpenRead(fileName))
            {
                return ReadPublicKey(keyIn);
            }
        }

        /**
         * A simple routine that opens a key ring file and loads the first available key
         * suitable for encryption.
         * 
         * @param input
         * @return
         * @throws IOException
         * @throws PGPException
         */
        public static PgpPublicKey ReadPublicKey(Stream input)
        {
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(
                PgpUtilities.GetDecoderStream(input));

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        public static PgpSecretKey ReadSecretKey(string fileName)
        {
            using (Stream keyIn = File.OpenRead(fileName))
            {
                return ReadSecretKey(keyIn);
            }
        }

        /**
         * A simple routine that opens a key ring file and loads the first available key
         * suitable for signature generation.
         * 
         * @param input stream to read the secret key ring collection from.
         * @return a secret key.
         * @throws IOException on a problem with using the input stream.
         * @throws PGPException if there is an issue parsing the input stream.
         */
        public static PgpSecretKey ReadSecretKey(Stream input)
        {
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                PgpUtilities.GetDecoderStream(input));

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            foreach (PgpSecretKeyRing keyRing in pgpSec.GetKeyRings())
            {
                foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                {
                    if (key.IsSigningKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");
        }

    }

    public static class ByteArrayHandler
    {

        /**
        * decrypt the passed in message stream
        *
        * @param encrypted  The message to be decrypted.
        * @param passPhrase Pass phrase (key)
        *
        * @return Clear text as a byte array.  I18N considerations are
        *         not handled by this routine
        * @exception IOException
        * @exception PgpException
        */
        public static byte[] Decrypt(
            byte[] encrypted,
            char[] passPhrase)
        {
            Stream inputStream = new MemoryStream(encrypted);

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
            PgpEncryptedDataList enc = null;
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

            PgpPbeEncryptedData pbe = (PgpPbeEncryptedData)enc[0];

            Stream clear = pbe.GetDataStream(passPhrase);

            PgpObjectFactory pgpFact = new PgpObjectFactory(clear);

            PgpCompressedData cData = (PgpCompressedData)pgpFact.NextPgpObject();

            pgpFact = new PgpObjectFactory(cData.GetDataStream());

            PgpLiteralData ld = (PgpLiteralData)pgpFact.NextPgpObject();

            Stream unc = ld.GetInputStream();

            return Streams.ReadAll(unc);
        }

        /**
        * Simple PGP encryptor between byte[].
        *
        * @param clearData  The test to be encrypted
        * @param passPhrase The pass phrase (key).  This method assumes that the
        *                   key is a simple pass phrase, and does not yet support
        *                   RSA or more sophisiticated keying.
        * @param fileName   File name. This is used in the Literal Data Packet (tag 11)
        *                   which is really inly important if the data is to be
        *                   related to a file to be recovered later.  Because this
        *                   routine does not know the source of the information, the
        *                   caller can set something here for file name use that
        *                   will be carried.  If this routine is being used to
        *                   encrypt SOAP MIME bodies, for example, use the file name from the
        *                   MIME type, if applicable. Or anything else appropriate.
        *
        * @param armor
        *
        * @return encrypted data.
        * @exception IOException
        * @exception PgpException
        */
        public static byte[] Encrypt(
            byte[] clearData,
            char[] passPhrase,
            string fileName,
            SymmetricKeyAlgorithmTag algorithm,
            bool armor)
        {
            if (fileName == null)
            {
                fileName = PgpLiteralData.Console;
            }

            byte[] compressedData = Compress(clearData, fileName, CompressionAlgorithmTag.Zip);

            MemoryStream bOut = new MemoryStream();

            Stream output = bOut;
            if (armor)
            {
                output = new ArmoredOutputStream(output);
            }

            PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(algorithm, new SecureRandom());
            encGen.AddMethod(passPhrase);

            Stream encOut = encGen.Open(output, compressedData.Length);

            encOut.Write(compressedData, 0, compressedData.Length);
            encOut.Close();

            if (armor)
            {
                output.Close();
            }

            return bOut.ToArray();
        }

        public static byte[] Compress(byte[] clearData, string fileName, CompressionAlgorithmTag algorithm)
        {
            MemoryStream bOut = new MemoryStream();

            PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(algorithm);
            Stream cos = comData.Open(bOut); // open it with the final destination
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();

            // we want to Generate compressed data. This might be a user option later,
            // in which case we would pass in bOut.
            Stream pOut = lData.Open(
                cos,					// the compressed output stream
                PgpLiteralData.Binary,
                fileName,				// "filename" to store
                clearData.Length,		// length of clear data
                DateTime.UtcNow			// current time
            );

            pOut.Write(clearData, 0, clearData.Length);
            pOut.Close();

            comData.Close();

            return bOut.ToArray();
        }

        public static string GetAsciiString(byte[] bs)
        {
            return Encoding.ASCII.GetString(bs, 0, bs.Length);
        }
    }

    public sealed class DetachedSignatureProcessor
    {
        private DetachedSignatureProcessor()
        {
        }

        public static bool VerifySignature(
            string fileName,
            string Signature,
            string keyFileName)
        {
            using (Stream input = File.OpenRead(Signature),
                keyIn = File.OpenRead(keyFileName))
            {
                return VerifySignature(fileName, input, keyIn);
            }
        }

        /**
        * verify the signature in in against the file fileName.
        */
        public static bool VerifySignature(
            string fileName,
            Stream Signature,
            Stream keyIn)
        {
            Signature = PgpUtilities.GetDecoderStream(Signature);

            PgpObjectFactory pgpFact = new PgpObjectFactory(Signature);
            PgpSignatureList p3 = null;
            PgpObject o = pgpFact.NextPgpObject();
            if (o is PgpCompressedData)
            {
                PgpCompressedData c1 = (PgpCompressedData)o;
                pgpFact = new PgpObjectFactory(c1.GetDataStream());

                p3 = (PgpSignatureList)pgpFact.NextPgpObject();
            }
            else
            {
                p3 = (PgpSignatureList)o;
            }

            PgpPublicKeyRingBundle pgpPubRingCollection = new PgpPublicKeyRingBundle(
                PgpUtilities.GetDecoderStream(keyIn));
            Stream dIn = File.OpenRead(fileName);
            PgpSignature sig = p3[0];
            PgpPublicKey key = pgpPubRingCollection.GetPublicKey(sig.KeyId);
            sig.InitVerify(key);

            int ch;
            while ((ch = dIn.ReadByte()) >= 0)
            {
                sig.Update((byte)ch);
            }

            dIn.Close();

            if (sig.Verify())
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public static void CreateSignature(
            string inputFileName,
            string keyFileName,
            string outputFileName,
            char[] pass,
            bool armor)
        {
            using (Stream keyIn = File.OpenRead(keyFileName),
                output = File.OpenWrite(outputFileName))
            {
                CreateSignature(inputFileName, keyIn, output, pass, armor);
            }
        }

        public static void CreateSignature(
            string fileName,
            Stream keyIn,
            Stream outputStream,
            char[] pass,
            bool armor)
        {
            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }

            PgpSecretKey pgpSec = KeyUtilities.ReadSecretKey(keyIn);
            PgpPrivateKey pgpPrivKey = pgpSec.ExtractPrivateKey(pass);
            PgpSignatureGenerator sGen = new PgpSignatureGenerator(
                pgpSec.PublicKey.Algorithm, HashAlgorithmTag.Sha1);

            sGen.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);

            BcpgOutputStream bOut = new BcpgOutputStream(outputStream);

            Stream fIn = File.OpenRead(fileName);

            int ch;
            while ((ch = fIn.ReadByte()) >= 0)
            {
                sGen.Update((byte)ch);
            }

            fIn.Close();

            sGen.Generate().Encode(bOut);

            if (armor)
            {
                outputStream.Close();
            }
        }

        public static void CreateSignature(
            string fileName,
            PgpSecretKey keyIn,
            Stream outputStream,
            char[] pass,
            bool armor)
        {
            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }

            
            PgpPrivateKey pgpPrivKey = keyIn.ExtractPrivateKey(pass);
            PgpSignatureGenerator sGen = new PgpSignatureGenerator(
                keyIn.PublicKey.Algorithm, HashAlgorithmTag.Sha1);

            sGen.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);

            BcpgOutputStream bOut = new BcpgOutputStream(outputStream);

            Stream fIn = File.OpenRead(fileName);

            int ch;
            while ((ch = fIn.ReadByte()) >= 0)
            {
                sGen.Update((byte)ch);
            }

            fIn.Close();

            sGen.Generate().Encode(bOut);

            if (armor)
            {
                outputStream.Close();
            }
        }
    }

    public class PGPEncryptDecrypt
    {

        /**
        * A simple routine that opens a key ring file and loads the first available key suitable for
        * encryption.
        *
        * @param in
        * @return
        * @m_out
        * @
        */

        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);
            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //
            //
            // iterate through the key rings.
            //

            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                    {
                        return k;
                    }
                }
            }
            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        /**
        * Search a secret key ring collection for a secret key corresponding to
        * keyId if it exists.
        *
        * @param pgpSec a secret key ring collection.
        * @param keyId keyId we want.
        * @param pass passphrase to decrypt secret key with.
        * @return
        */

        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);
            if (pgpSecKey == null)
            {
                return null;
            }
            return pgpSecKey.ExtractPrivateKey(pass);
        }

        /**
        * decrypt the passed in message stream
        */
        public static void DecryptFile(Stream inputStream, Stream keyIn, char[] passwd, string pathToSaveFile)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            try
            {

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
                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                PgpUtilities.GetDecoderStream(keyIn));

                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    sKey = FindSecretKey(pgpSec, pked.KeyId, passwd);

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

                    //string outFileName = ld.FileName;
                    //if (outFileName.Length == 0)

                    //{

                    //    outFileName = defaultFileName;

                    //}

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
                        Console.WriteLine("message failed integrity check");
                    }

                    else
                    {
                        Console.WriteLine("message integrity check passed");
                    }
                }

                else
                {
                    Console.WriteLine("no message integrity check");
                }
            }

            catch (PgpException e)
            {
                Console.WriteLine(e);
                Exception underlyingException = e.InnerException;

                if (underlyingException != null)
                {
                    Console.WriteLine(underlyingException.Message);
                    Console.WriteLine(underlyingException.StackTrace);
                }
            }
        }

        public static void EncryptFile(Stream outputStream, string fileName, PgpPublicKey encKey, bool armor, bool withIntegrityCheck)
        {
            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }

            try
            {
                MemoryStream bOut = new MemoryStream();
                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(
                CompressionAlgorithmTag.Zip);
                PgpUtilities.WriteFileToLiteralData(
                comData.Open(bOut),
                PgpLiteralData.Binary,
                new FileInfo(fileName));
                comData.Close();
                PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(
                SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
                cPk.AddMethod(encKey);
                byte[] bytes = bOut.ToArray();
                Stream cOut = cPk.Open(outputStream, bytes.Length);
                cOut.Write(bytes, 0, bytes.Length);
                cOut.Close();
                if (armor)
                {
                    outputStream.Close();
                }
            }

            catch (PgpException e)
            {
                Console.WriteLine(e);
                Exception underlyingException = e.InnerException;

                if (underlyingException != null)
                {
                    Console.WriteLine(underlyingException.Message);
                    Console.WriteLine(underlyingException.StackTrace);
                }
            }
        }

        public static void Encrypt(string filePath, string OutputFilePath, string publicKeyFile)
        {
            Stream keyIn, fos;
            keyIn = File.OpenRead(publicKeyFile);
            fos = File.Create(OutputFilePath);
            EncryptFile(fos, filePath, ReadPublicKey(keyIn), true, true);
            keyIn.Close();
            fos.Close();
        }

        public static void Decrypt(string filePath, string privateKeyFile, string passPhrase, string pathToSaveFile)
        {

            Stream fin = File.OpenRead(filePath);
            Stream keyIn = File.OpenRead(privateKeyFile);
            DecryptFile(fin, keyIn, passPhrase.ToCharArray(), pathToSaveFile);
            fin.Close();
            keyIn.Close();
        }

        public void SignAndEncryptFile(string actualFileName, 
               string embeddedFileName,
               Stream SignKey, 
               long keyId, 
               string OutputFileName,
               char[] password, 
               bool armor, 
               bool withIntegrityCheck, 
               PgpPublicKey encKey)
        {

            const int BUFFER_SIZE = 1 << 16; // should always be power of 2
            Stream outputStream = File.Open(OutputFileName, FileMode.Create);

            if (armor)
                outputStream = new ArmoredOutputStream(outputStream);

            // Init encrypted data generator
            PgpEncryptedDataGenerator encryptedDataGenerator =
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());

            encryptedDataGenerator.AddMethod(encKey);
            Stream encryptedOut = encryptedDataGenerator.Open(outputStream, new byte[BUFFER_SIZE]);

            // Init compression

            PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            Stream compressedOut = compressedDataGenerator.Open(encryptedOut);

            // Init signature

            PgpSecretKeyRingBundle pgpSecBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(SignKey));
            PgpSecretKey pgpSecKey = pgpSecBundle.GetSecretKey(keyId);

            if (pgpSecKey == null)

                throw new ArgumentException(keyId.ToString("X") + " could not be found in specified key ring bundle.", "keyId");

            PgpPrivateKey pgpPrivKey = pgpSecKey.ExtractPrivateKey(password);
            PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, HashAlgorithmTag.Sha1);
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

            // TODO: Use lastwritetime from source file
            Stream literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Binary,
                embeddedFile.Name, actualFile.LastWriteTime, new byte[BUFFER_SIZE]);

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
