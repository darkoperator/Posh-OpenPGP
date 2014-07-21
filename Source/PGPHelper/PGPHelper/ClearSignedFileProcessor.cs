using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;

namespace PGPHelper
{

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

            var lookAhead = -1;
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

            var ch = lookAhead;

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
            var lookAhead = fIn.ReadByte();

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
        public static PgpSignatureInfo VerifyFile(
            Stream inputStream,
            Stream pubkeyRing)
        {
            var aIn = new ArmoredInputStream(inputStream);

            Stream outStr = new MemoryStream();
            //
            // write out signed section using the local line separator.
            // note: trailing white space needs to be removed from the end of
            // each line RFC 4880 Section 7.1
            //
            var lineOut = new MemoryStream();
            var lookAhead = ReadInputLine(lineOut, aIn);
            var newline = Encoding.ASCII.GetBytes(Environment.NewLine);

            if (lookAhead != -1 && aIn.IsClearText())
            {
                var line = lineOut.ToArray();
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

            var pgpRings = new PgpPublicKeyRingBundle(pubkeyRing);

            var pgpFact = new PgpObjectFactory(aIn);
            var p3 = (PgpSignatureList)pgpFact.NextPgpObject();
            var sig = p3[0];

            sig.InitVerify(pgpRings.GetPublicKey(sig.KeyId));

            //
            // read the input, making sure we ignore the last newline.
            //
            var sigIn = outStr;

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

            // Instanciate signature generator.
            var sGen = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, digest);
            var spGen = new PgpSignatureSubpacketGenerator();

            // Extract private key
            PgpPrivateKey pgpPrivKey;
            try
            {
                pgpPrivKey = pgpSecKey.ExtractPrivateKey(pass);
                sGen.InitSign(PgpSignature.CanonicalTextDocument, pgpPrivKey);
            }
            catch
            {
                throw new PgpException("Wrong Passphrase, could not extract private key.");
            }

            var enumerator = pgpSecKey.PublicKey.GetUserIds().GetEnumerator();
            if (enumerator.MoveNext())
            {
                spGen.SetSignerUserId(false, (string)enumerator.Current);
                sGen.SetHashedSubpackets(spGen.Generate());
            }

            var aOut = new ArmoredOutputStream(outputStream);
            if (version)
            {
                aOut.SetHeader("Version", "Posh-OpenPGP");
            }

            aOut.BeginClearText(digest);

            //
            // note the last \n/\r/\r\n in the file is ignored
            //
            var lineOut = new MemoryStream();
            var lookAhead = ReadInputLine(lineOut, fIn);
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
            var bOut = new BcpgOutputStream(aOut);
            sGen.Generate().Encode(bOut);
            aOut.Close();
        }


        private static void ProcessLine(
            PgpSignature sig,
            byte[] line)
        {
            // note: trailing white space needs to be removed from the end of
            // each line for signature calculation RFC 4880 Section 7.1
            var length = GetLengthWithoutWhiteSpace(line);
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
            var length = GetLengthWithoutWhiteSpace(line);
            if (length > 0)
            {
                sGen.Update(line, 0, length);
            }
            aOut.Write(line, 0, line.Length);
        }

        private static int GetLengthWithoutSeparatorOrTrailingWhitespace(byte[] line)
        {
            var end = line.Length - 1;
            while (end >= 0 && IsWhiteSpace(line[end]))
            {
                end--;
            }
            return end + 1;
        }

        private static bool IsLineEnding(byte b)
        {
            return b == '\r' || b == '\n';
        }

        private static int GetLengthWithoutWhiteSpace(byte[] line)
        {
            var end = line.Length - 1;
            while (end >= 0 && IsWhiteSpace(line[end]))
            {
                end--;
            }
            return end + 1;
        }

        private static bool IsWhiteSpace(byte b)
        {
            return IsLineEnding(b) || b == '\t' || b == ' ';
        }

    }
}
