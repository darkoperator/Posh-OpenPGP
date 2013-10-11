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
}
