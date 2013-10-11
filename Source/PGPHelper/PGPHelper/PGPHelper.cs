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

