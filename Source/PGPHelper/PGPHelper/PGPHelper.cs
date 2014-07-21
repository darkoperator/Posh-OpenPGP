using System;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;


// code from examples that came with bouncy castle :) and modified.
// why re-invent the wheel.

namespace PGPHelper
{
    public class PgpSignatureInfo
    {
        public bool Valid;
        public DateTime Created;
        public string KeyId;
        public HashAlgorithmTag HashAlgorithm;
        public int Version;
        public PgpSignature Signature;
    }
}

