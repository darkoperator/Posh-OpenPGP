using System;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;

namespace PGPHelper
{
    public sealed class DetachedSignedFileProcessor
    {


        public static PgpSignatureInfo VerifySignature(
            string fileName,
            string signature,
            string keyFileName)
        {
            using (Stream input = File.OpenRead(signature),
                keyIn = File.OpenRead(keyFileName))
            {
                return VerifySignature(fileName, input, keyIn);
            }
        }

        /**
        * verify the signature in in against the file fileName.
        */
        public static PgpSignatureInfo VerifySignature(
            string fileName,
            Stream signature,
            Stream keyIn)
        {
            signature = PgpUtilities.GetDecoderStream(signature);

            var pgpFact = new PgpObjectFactory(signature);
            PgpSignatureList p3;
            var o = pgpFact.NextPgpObject();
            var data = o as PgpCompressedData;
            if (data != null)
            {
                var c1 = data;
                pgpFact = new PgpObjectFactory(c1.GetDataStream());

                p3 = (PgpSignatureList)pgpFact.NextPgpObject();
            }
            else
            {
                p3 = (PgpSignatureList)o;
            }

            var pgpPubRingCollection = new PgpPublicKeyRingBundle(
                PgpUtilities.GetDecoderStream(keyIn));
            Stream dIn = File.OpenRead(fileName);
            var sig = p3[0];
            var key = pgpPubRingCollection.GetPublicKey(sig.KeyId);
            sig.InitVerify(key);

            int ch;
            while ((ch = dIn.ReadByte()) >= 0)
            {
                sig.Update((byte)ch);
            }

            dIn.Close();

            var siginfo = new PgpSignatureInfo();

            if (sig.Verify())
            {
                siginfo.KeyId = String.Format("{0:X}", sig.KeyId);
                siginfo.Valid = true;
                siginfo.Version = sig.Version;
                siginfo.Created = sig.CreationTime;
                siginfo.HashAlgorithm = sig.HashAlgorithm;
                siginfo.Signature = sig;
                return siginfo;
            }
            siginfo.KeyId = String.Format("{0:X}", sig.KeyId);
            siginfo.Valid = false;
            siginfo.Version = sig.Version;
            siginfo.Created = sig.CreationTime;
            siginfo.HashAlgorithm = sig.HashAlgorithm;
            siginfo.Signature = sig;

            return siginfo;
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
            var pgpSec = KeyUtilities.ReadSecretKey(keyIn);
            var pgpPrivKey = pgpSec.ExtractPrivateKey(pass);

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


            var sGen = new PgpSignatureGenerator(
                pgpSec.PublicKey.Algorithm, digest);

            sGen.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);

            var bOut = new BcpgOutputStream(outputStream);

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

            var pgpPrivKey = keyIn.ExtractPrivateKey(pass);
            var sGen = new PgpSignatureGenerator(
                keyIn.PublicKey.Algorithm, digest);

            sGen.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);

            var bOut = new BcpgOutputStream(outputStream);

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
}
