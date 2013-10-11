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
}
