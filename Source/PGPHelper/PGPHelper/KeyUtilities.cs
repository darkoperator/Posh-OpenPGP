using System;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;

namespace PGPHelper
{
    public static class KeyUtilities
    {
        internal static byte[] CompressFile(string fileName, CompressionAlgorithmTag algorithm)
        {
            var bOut = new MemoryStream();
            var comData = new PgpCompressedDataGenerator(algorithm);
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
        public static PgpPrivateKey FindSecretKeybyKeyId(PgpSecretKeyRingBundle pgpSec, long keyID, char[] pass)
        {
            var pgpSecKey = pgpSec.GetSecretKey(keyID);

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        public static PgpPrivateKey FindSecretKeybyKeyId(PgpSecretKeyRingBundle pgpSec, string keyID, char[] pass)
        {
            var pgpSecKey = pgpSec.GetSecretKey(System.Convert.ToInt64(keyID, 16));

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        public static PgpPrivateKey FindSecretKeyByUserId(PgpSecretKeyRingBundle pgpSec, string userId, char[] pass)
        {
            foreach (PgpSecretKeyRing keyRing in pgpSec.GetKeyRings(userId, true, true))
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

        public static PgpPublicKey FindPublicKeyByKeyId(PgpPublicKeyRingBundle pgpPub, long keyId)
        {
            var pgpPubKey = pgpPub.GetPublicKey(keyId);

            if (pgpPubKey == null)
            {
                return null;
            }

            return pgpPubKey;
        }

        public static PgpPublicKey[] FindPublicKeyByKeyId(PgpPublicKeyRingBundle pgpPub, string[] keyIDs)
        {
            var pubKeyList = new PgpPublicKey[50];
            var index = 0;

            foreach (var pubKeyId in keyIDs)
            {
                var pgpPubKey = pgpPub.GetPublicKey(System.Convert.ToInt64(pubKeyId, 16));

                if (pgpPubKey != null)
                {
                    pubKeyList[index] = pgpPubKey;
                    index++;
                }
            }
            return pubKeyList;
        }

        public static PgpPublicKey[] FindPublicKeyByKeyId(PgpPublicKeyRingBundle pgpPub, long[] keyIDs)
        {
            var pubKeyList = new PgpPublicKey[50];
            var index = 0;

            foreach (var pubKeyId in keyIDs)
            {
                var pgpPubKey = pgpPub.GetPublicKey(pubKeyId);

                if (pgpPubKey != null)
                {
                    pubKeyList[index] = pgpPubKey;
                    index++;
                }
            }
            return pubKeyList;
        }

        public static PgpPublicKey[] FindPublicKeyByUserId(PgpPublicKeyRingBundle pgpPub, string userId)
        {
            var Keys = new PgpPublicKey[50];
            var Index = 0;
            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings(userId, true, true))
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

        public static PgpPublicKey[] FindPublicKeybyUserId(PgpPublicKeyRingBundle pgpPub, string[] userIDs, char[] pass)
        {
            var keys = new PgpPublicKey[50];
            var index = 0;
            foreach (var userId in userIDs)
            {
                foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings(userId, true, true))
                {
                    foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                    {

                        keys[index] = key;
                        index++;
                    }
                }
            }
            if (keys.Length > 0)
            {
                return keys;
            }
            return null;
        }

        public static PgpPublicKeyRingBundle ReadPublicKeBundle(string fileName)
        {
            using (Stream keyIn = File.OpenRead(fileName))
            {
                var pgpPub = new PgpPublicKeyRingBundle(
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
            var pgpPub = new PgpPublicKeyRingBundle(
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
            var pgpSec = new PgpSecretKeyRingBundle(
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
