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


// code from examples that came with bouncy castle :) and modified.
// why re-invent the wheel.

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
        public static PgpPrivateKey FindSecretKeybyKeyID(PgpSecretKeyRingBundle pgpSec, long keyID, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyID);

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        public static PgpPrivateKey FindSecretKeybyKeyID(PgpSecretKeyRingBundle pgpSec, string keyID, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(System.Convert.ToInt64(keyID, 16));

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        public static PgpPrivateKey FindSecretKeyByUserID(PgpSecretKeyRingBundle pgpSec, string UserID, char[] pass)
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

        public static PgpPublicKey FindPublicKeyByKeyID(PgpPublicKeyRingBundle pgpPub, long keyID)
        {
            PgpPublicKey pgpPubKey = pgpPub.GetPublicKey(keyID);

            if (pgpPubKey == null)
            {
                return null;
            }

            return pgpPubKey;
        }

        public static PgpPublicKey[] FindPublicKeyByKeyID(PgpPublicKeyRingBundle pgpPub, string[] keyIDs)
        {
            PgpPublicKey[] pubKeyList = new PgpPublicKey[50];
            int index = 0;

            foreach (string pubKeyId in keyIDs)
            {
                PgpPublicKey pgpPubKey = pgpPub.GetPublicKey(System.Convert.ToInt64(pubKeyId, 16));

                if (pgpPubKey != null)
                {
                    pubKeyList[index] = pgpPubKey;
                    index++;
                }
            }
            return pubKeyList;
        }

        public static PgpPublicKey[] FindPublicKeyByKeyID(PgpPublicKeyRingBundle pgpPub, long[] keyIDs)
        {
            PgpPublicKey[] pubKeyList = new PgpPublicKey[50];
            int index = 0;

            foreach (long pubKeyId in keyIDs)
            {
                PgpPublicKey pgpPubKey = pgpPub.GetPublicKey(pubKeyId);

                if (pgpPubKey != null)
                {
                    pubKeyList[index] = pgpPubKey;
                    index++;
                }
            }
            return pubKeyList;
        }

        public static PgpPublicKey[] FindPublicKeyByUserID(PgpPublicKeyRingBundle pgpPub, string UserID)
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

        public static PgpPublicKey[] FindPublicKeybyUserID(PgpPublicKeyRingBundle pgpPub, string[] UserIDs, char[] pass)
        {
            PgpPublicKey[] Keys = new PgpPublicKey[50];
            int Index = 0;
            foreach (string UserID in UserIDs)
            {
                foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings(UserID, true, true))
                {
                    foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                    {

                        Keys[Index] = key;
                        Index++;
                    }
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

    public static class SymmetricFileProcessor
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
        public static byte[] Decrypt(byte[] encrypted, char[] passPhrase)
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
            bool armor,
            string compressionName,
            bool verinfo = false,
            string comment = "")
        {
            if (fileName == null)
            {
                fileName = PgpLiteralData.Console;
            }

            // Select the specified compression
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

            // Compress the data.

            byte[] compressedData = Compress(clearData, fileName, comptype);

            MemoryStream bOut = new MemoryStream();

            // Set the Armour stream and info.
            Stream output = bOut;
            ArmoredOutputStream Aoutput = new ArmoredOutputStream(output);
            if (armor)
            {
                if (verinfo)
                {
                    Aoutput.SetHeader("Version", "Posh-OpenPGP");
                }
                if (comment.Length > 0)
                {
                    Aoutput.SetHeader("Comment", comment);
                }
            }

            // Encrypt the data.
            PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(algorithm, new SecureRandom());
            encGen.AddMethod(passPhrase);
            Stream encOut;
            if (armor)
            {
                encOut = encGen.Open(Aoutput, compressedData.Length);
            }
            else
            {
                encOut = encGen.Open(output, compressedData.Length);
            }
            encOut.Write(compressedData, 0, compressedData.Length);
            encOut.Close();

            if (armor)
            {
                Aoutput.Close();
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

    public sealed class DetachedSignedFileProcessor
    {


        public static PGPSignatureInfo VerifySignature(
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
        public static PGPSignatureInfo VerifySignature(
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

            PGPSignatureInfo siginfo = new PGPSignatureInfo();

            if (sig.Verify())
            {
                siginfo.KeyID = String.Format("{0:X}", sig.KeyId);
                siginfo.Valid = true;
                siginfo.Version = sig.Version;
                siginfo.Created = sig.CreationTime;
                siginfo.HashAlgorithm = sig.HashAlgorithm;
                siginfo.Signature = sig;
                return siginfo;
            }
            else
            {
                siginfo.KeyID = String.Format("{0:X}", sig.KeyId);
                siginfo.Valid = false;
                siginfo.Version = sig.Version;
                siginfo.Created = sig.CreationTime;
                siginfo.HashAlgorithm = sig.HashAlgorithm;
                siginfo.Signature = sig;

                return siginfo;
            }
        }

        public static void CreateSignature(
            string inputFileName,
            string keyFileName,
            string outputFileName,
            char[] pass,
            bool armor,
            string digestName)
        {
            using (Stream keyIn = File.OpenRead(keyFileName),
                output = File.OpenWrite(outputFileName))
            {
                CreateSignature(inputFileName, keyIn, output, pass, armor, digestName);
            }
        }

        public static void CreateSignature(
            string fileName,
            Stream keyIn,
            Stream outputStream,
            char[] pass,
            bool armor,
            string digestName)
        {
            PgpSecretKey pgpSec = KeyUtilities.ReadSecretKey(keyIn);
            PgpPrivateKey pgpPrivKey = pgpSec.ExtractPrivateKey(pass);

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


            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }

          
            PgpSignatureGenerator sGen = new PgpSignatureGenerator(
                pgpSec.PublicKey.Algorithm, digest);

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
            bool armor,
            string digestName)
        {
            if (armor)
            {
                 outputStream = new ArmoredOutputStream(outputStream);
                
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

            PgpPrivateKey pgpPrivKey = keyIn.ExtractPrivateKey(pass);
            PgpSignatureGenerator sGen = new PgpSignatureGenerator(
                keyIn.PublicKey.Algorithm, digest);

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

    public sealed class ClearSignedFileProcessor
    {
        private ClearSignedFileProcessor()
        {
        }

        private static int ReadInputLine(
            MemoryStream bOut,
            Stream fIn)
        {
            bOut.SetLength(0);

            int lookAhead = -1;
            int ch;

            while ((ch = fIn.ReadByte()) >= 0)
            {
                bOut.WriteByte((byte)ch);
                if (ch == '\r' || ch == '\n')
                {
                    lookAhead = ReadPassedEol(bOut, ch, fIn);
                    break;
                }
            }

            return lookAhead;
        }

        private static int ReadInputLine(
            MemoryStream bOut,
            int lookAhead,
            Stream fIn)
        {
            bOut.SetLength(0);

            int ch = lookAhead;

            do
            {
                bOut.WriteByte((byte)ch);
                if (ch == '\r' || ch == '\n')
                {
                    lookAhead = ReadPassedEol(bOut, ch, fIn);
                    break;
                }
            }
            while ((ch = fIn.ReadByte()) >= 0);

            if (ch < 0)
            {
                lookAhead = -1;
            }

            return lookAhead;
        }

        private static int ReadPassedEol(
            MemoryStream bOut,
            int lastCh,
            Stream fIn)
        {
            int lookAhead = fIn.ReadByte();

            if (lastCh == '\r' && lookAhead == '\n')
            {
                bOut.WriteByte((byte)lookAhead);
                lookAhead = fIn.ReadByte();
            }

            return lookAhead;
        }

        /*
        * verify a clear text signed file
        */
        public static PGPSignatureInfo VerifyFile(
            Stream inputStream,
            Stream PubkeyRing)
        {
            ArmoredInputStream aIn = new ArmoredInputStream(inputStream);
            
            Stream outStr = new MemoryStream();
            //
            // write out signed section using the local line separator.
            // note: trailing white space needs to be removed from the end of
            // each line RFC 4880 Section 7.1
            //
            MemoryStream lineOut = new MemoryStream();
            int lookAhead = ReadInputLine(lineOut, aIn);
            byte[] newline = Encoding.ASCII.GetBytes(Environment.NewLine);

            if (lookAhead != -1 && aIn.IsClearText())
            {
                byte[] line = lineOut.ToArray();
                outStr.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                outStr.Write(newline, 0, newline.Length);

                while (lookAhead != -1 && aIn.IsClearText())
                {
                    lookAhead = ReadInputLine(lineOut, lookAhead, aIn);

                    line = lineOut.ToArray();
                    outStr.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                    outStr.Write(newline, 0, newline.Length);
                }
            }

            //outStr.Close();

            PgpPublicKeyRingBundle pgpRings = new PgpPublicKeyRingBundle(PubkeyRing);

            PgpObjectFactory pgpFact = new PgpObjectFactory(aIn);
            PgpSignatureList p3 = (PgpSignatureList)pgpFact.NextPgpObject();
            PgpSignature sig = p3[0];

            sig.InitVerify(pgpRings.GetPublicKey(sig.KeyId));

            //
            // read the input, making sure we ignore the last newline.
            //
            Stream sigIn = outStr;

            // Set position of stream to start.
            sigIn.Position = 0;
            lookAhead = ReadInputLine(lineOut, sigIn);

            ProcessLine(sig, lineOut.ToArray());

            if (lookAhead != -1)
            {
                do
                {
                    lookAhead = ReadInputLine(lineOut, lookAhead, sigIn);

                    sig.Update((byte)'\r');
                    sig.Update((byte)'\n');

                    ProcessLine(sig, lineOut.ToArray());
                }
                while (lookAhead != -1);
            }

            PGPSignatureInfo siginfo = new PGPSignatureInfo();

            if (sig.Verify())
            {
                siginfo.KeyID = String.Format("{0:X}", sig.KeyId);
                siginfo.Valid = true;
                siginfo.Version = sig.Version;
                siginfo.Created = sig.CreationTime;
                siginfo.HashAlgorithm = sig.HashAlgorithm;
                siginfo.Signature = sig;
                return siginfo;
            }
            else
            {
                siginfo.KeyID = String.Format("{0:X}", sig.KeyId);
                siginfo.Valid = false;
                siginfo.Version = sig.Version;
                siginfo.Created = sig.CreationTime;
                siginfo.HashAlgorithm = sig.HashAlgorithm;
                siginfo.Signature = sig;

                return siginfo;
            }
        }


        /*
        * create a clear text signed file.
        */
        public static void SignFile(
                    //string fileName,
                    Stream fIn,
                    PgpSecretKey pgpSecKey,
                    Stream outputStream,
                    char[] pass,
                    string digestName,
                    bool version = true
            )
        {
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


            PgpPrivateKey pgpPrivKey = pgpSecKey.ExtractPrivateKey(pass);
            PgpSignatureGenerator sGen = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, digest);
            PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator();

            sGen.InitSign(PgpSignature.CanonicalTextDocument, pgpPrivKey);

            IEnumerator enumerator = pgpSecKey.PublicKey.GetUserIds().GetEnumerator();
            if (enumerator.MoveNext())
            {
                spGen.SetSignerUserId(false, (string)enumerator.Current);
                sGen.SetHashedSubpackets(spGen.Generate());
            }

            //Stream fIn = File.OpenRead(fileName);
            ArmoredOutputStream aOut = new ArmoredOutputStream(outputStream);
            if (version)
            {
                aOut.SetHeader("Version", "Posh-OpenPGP");
            }

            aOut.BeginClearText(digest);

            //
            // note the last \n/\r/\r\n in the file is ignored
            //
            MemoryStream lineOut = new MemoryStream();
            int lookAhead = ReadInputLine(lineOut, fIn);

            ProcessLine(aOut, sGen, lineOut.ToArray());

            if (lookAhead != -1)
            {
                do
                {
                    lookAhead = ReadInputLine(lineOut, lookAhead, fIn);

                    sGen.Update((byte)'\r');
                    sGen.Update((byte)'\n');

                    ProcessLine(aOut, sGen, lineOut.ToArray());
                }
                while (lookAhead != -1);
            }

            fIn.Close();

            aOut.EndClearText();

            BcpgOutputStream bOut = new BcpgOutputStream(aOut);

            sGen.Generate().Encode(bOut);

            aOut.Close();
        }


        private static void ProcessLine(
            PgpSignature sig,
            byte[] line)
        {
            // note: trailing white space needs to be removed from the end of
            // each line for signature calculation RFC 4880 Section 7.1
            int length = GetLengthWithoutWhiteSpace(line);
            if (length > 0)
            {
                sig.Update(line, 0, length);
            }
        }

        private static void ProcessLine(
            Stream aOut,
            PgpSignatureGenerator sGen,
            byte[] line)
        {
            int length = GetLengthWithoutWhiteSpace(line);
            if (length > 0)
            {
                sGen.Update(line, 0, length);
            }

            aOut.Write(line, 0, line.Length);
        }

        private static int GetLengthWithoutSeparatorOrTrailingWhitespace(byte[] line)
        {
            int end = line.Length - 1;

            while (end >= 0 && IsWhiteSpace(line[end]))
            {
                end--;
            }

            return end + 1;
        }

        private static bool IsLineEnding(
            byte b)
        {
            return b == '\r' || b == '\n';
        }

        private static int GetLengthWithoutWhiteSpace(
            byte[] line)
        {
            int end = line.Length - 1;

            while (end >= 0 && IsWhiteSpace(line[end]))
            {
                end--;
            }

            return end + 1;
        }

        private static bool IsWhiteSpace(
            byte b)
        {
            return IsLineEnding(b) || b == '\t' || b == ' ';
        }

    }

    public class PGPEncryptDecrypt
    {

        /**
        * decrypt the passed in message stream
        */
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


        public static void EncryptFile(Stream outputStream, string fileName, PgpPublicKey[] encKeys, bool armor, bool withIntegrityCheck, string compressionName)
        {
            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
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

            try
            {
                MemoryStream bOut = new MemoryStream();
                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(
                comptype);
                PgpUtilities.WriteFileToLiteralData(
                comData.Open(bOut),
                PgpLiteralData.Binary,
                new FileInfo(fileName));
                comData.Close();
                PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(
                SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
                foreach(PgpPublicKey encKey in encKeys)
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

        // Based on http://jopinblog.wordpress.com/2008/06/23/pgp-single-pass-sign-and-encrypt-with-bouncy-castle/
 
        public void SignAndEncryptFile(string actualFileName, 
               string embeddedFileName,
               PgpSecretKey pgpSecKey, 
               long keyId, 
               string OutputFileName,
               char[] password, 
               bool armor, 
               bool withIntegrityCheck,
               PgpPublicKey[] encKeys,
               string compressionName,
               string  digestName)
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
                outputStream = new ArmoredOutputStream(outputStream);

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

            PgpPrivateKey pgpPrivKey = pgpSecKey.ExtractPrivateKey(password);
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


    public class PGPSignatureInfo
    {
        public bool Valid;
        public DateTime Created;
        public string KeyID;
        public HashAlgorithmTag HashAlgorithm;
        public int Version;
        public PgpSignature Signature;
    }
}

