using System.Buffers.Binary;
using System.Text;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.SoftEther;
using TqkLibrary.VpnClient.SoftEther.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.SoftEther.Tests
{
    /// <summary>
    /// Offline tests for the SoftEther PACK codec: round-trip of every value type, multi-value arrays, max-length
    /// element names, and byte-exact layout assertions against PACKs hand-built from the protocol spec (hello/login
    /// fields). No network, no Integration trait.
    /// </summary>
    public class PackCodecTests
    {
        // ---- Round-trip every value type -------------------------------------------------------------

        [Fact]
        public void RoundTrip_Int_PreservesValue()
        {
            var pack = new Pack().SetInt("max_connection", 0x12345678u);
            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.Equal(0x12345678u, parsed.GetInt("max_connection"));
            Assert.Equal(PackValueType.Int, parsed.GetElement("max_connection")!.Type);
        }

        [Fact]
        public void RoundTrip_Int64_PreservesValue()
        {
            var pack = new Pack().SetInt64("timestamp", 0x0102030405060708ul);
            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.Equal(0x0102030405060708ul, parsed.GetInt64("timestamp"));
        }

        [Fact]
        public void RoundTrip_Data_PreservesBytes()
        {
            byte[] random = Enumerable.Range(0, 20).Select(i => (byte)(i * 7 + 1)).ToArray();
            var pack = new Pack().SetData("random", random);
            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.Equal(random, parsed.GetData("random"));
        }

        [Fact]
        public void RoundTrip_Str_PreservesAnsiString()
        {
            var pack = new Pack().SetStr("hubname", "VPNGATE");
            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.Equal("VPNGATE", parsed.GetStr("hubname"));
        }

        [Fact]
        public void RoundTrip_UniStr_PreservesUnicodeString()
        {
            // Non-ASCII to exercise the UTF-8 path of UNISTR.
            var pack = new Pack().SetUniStr("note", "Xin chào — 日本語 €");
            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.Equal("Xin chào — 日本語 €", parsed.GetUniStr("note"));
        }

        [Fact]
        public void RoundTrip_Bool_PreservesValue()
        {
            var pack = new Pack().SetBool("use_encrypt", true).SetBool("use_compress", false);
            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.True(parsed.GetBool("use_encrypt"));
            Assert.False(parsed.GetBool("use_compress"));
        }

        [Fact]
        public void RoundTrip_EmptyData_AndEmptyString()
        {
            var pack = new Pack()
                .SetData("empty_data", Array.Empty<byte>())
                .SetStr("empty_str", string.Empty)
                .SetUniStr("empty_uni", string.Empty);
            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.Equal(Array.Empty<byte>(), parsed.GetData("empty_data"));
            Assert.Equal(string.Empty, parsed.GetStr("empty_str"));
            Assert.Equal(string.Empty, parsed.GetUniStr("empty_uni"));
        }

        // ---- Multi-value arrays ----------------------------------------------------------------------

        [Fact]
        public void RoundTrip_IntArray_PreservesAllValues()
        {
            uint[] ports = { 443u, 992u, 5555u, 8888u };
            var pack = new Pack().SetIntArray("ports", ports);
            Pack parsed = Pack.Parse(pack.ToBytes());
            PackElement element = parsed.GetElement("ports")!;
            Assert.Equal(4, element.ValueCount);
            for (int i = 0; i < ports.Length; i++)
                Assert.Equal(ports[i], parsed.GetInt("ports", i));
        }

        [Fact]
        public void RoundTrip_StrArray_PreservesAllValues()
        {
            string[] cipher = { "AES128-SHA", "AES256-SHA", "RC4-MD5" };
            var pack = new Pack().SetStrArray("cipher_list", cipher);
            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.Equal(3, parsed.GetElement("cipher_list")!.ValueCount);
            for (int i = 0; i < cipher.Length; i++)
                Assert.Equal(cipher[i], parsed.GetStr("cipher_list", i));
        }

        [Fact]
        public void RoundTrip_DataArray_PreservesAllValues()
        {
            byte[][] blobs = { new byte[] { 1, 2, 3 }, Array.Empty<byte>(), new byte[] { 9, 8, 7, 6, 5 } };
            var pack = new Pack().SetDataArray("blobs", blobs);
            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.Equal(3, parsed.GetElement("blobs")!.ValueCount);
            for (int i = 0; i < blobs.Length; i++)
                Assert.Equal(blobs[i], parsed.GetData("blobs", i));
        }

        // ---- Name length boundaries ------------------------------------------------------------------

        [Fact]
        public void MaxLengthName_RoundTrips()
        {
            string name = new string('a', PackConstants.MaxElementNameLength); // 63 chars
            var pack = new Pack().SetInt(name, 42u);
            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.Equal(63, name.Length);
            Assert.Equal(42u, parsed.GetInt(name));
            Assert.NotNull(parsed.GetElement(name));
        }

        [Fact]
        public void NameOverLimit_Throws()
        {
            string tooLong = new string('a', PackConstants.MaxElementNameLength + 1);
            Assert.Throws<ArgumentException>(() => new Pack().SetInt(tooLong, 1u));
        }

        // ---- Lookup semantics ------------------------------------------------------------------------

        [Fact]
        public void GetElement_IsCaseInsensitive()
        {
            var pack = new Pack().SetStr("HubName", "DEFAULT");
            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.Equal("DEFAULT", parsed.GetStr("hubname"));
            Assert.Equal("DEFAULT", parsed.GetStr("HUBNAME"));
        }

        [Fact]
        public void DuplicateName_OnAdd_Throws()
        {
            var pack = new Pack().SetInt("x", 1u);
            Assert.Throws<ArgumentException>(() => pack.SetInt("X", 2u)); // case-insensitive collision
        }

        [Fact]
        public void TypeMismatchOrMissing_ReturnsFallback()
        {
            var pack = new Pack().SetInt("n", 5u);
            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.Equal(0u, parsed.GetInt("missing"));            // absent
            Assert.Null(parsed.GetStr("n"));                       // wrong type
            Assert.Equal(99u, parsed.GetInt("missing", 0, 99u));   // explicit fallback
        }

        // ---- Byte-exact layout vs hand-built spec PACKs ----------------------------------------------

        [Fact]
        public void ByteLayout_SingleIntElement_MatchesSpec()
        {
            // PACK { "test": INT(0x01020304) }
            // num_elements=1 | BufStr("test")=[00 00 00 05]['t''e''s''t'] | type=INT(0)[00 00 00 00]
            //   | num_value=1[00 00 00 01] | value=01 02 03 04
            byte[] actual = new Pack().SetInt("test", 0x01020304u).ToBytes();
            byte[] expected =
            {
                0x00, 0x00, 0x00, 0x01,             // num_elements = 1
                0x00, 0x00, 0x00, 0x05,             // name length prefix = 4 + 1
                (byte)'t', (byte)'e', (byte)'s', (byte)'t',
                0x00, 0x00, 0x00, 0x00,             // type = INT (0)
                0x00, 0x00, 0x00, 0x01,             // num_value = 1
                0x01, 0x02, 0x03, 0x04,             // value
            };
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void ByteLayout_StrElement_HasNoPlusOneOnValueLength()
        {
            // VALUE_STR length prefix is the EXACT byte length (no +1), unlike the element-name BufStr (+1).
            byte[] actual = new Pack().SetStr("a", "hi").ToBytes();
            byte[] expected =
            {
                0x00, 0x00, 0x00, 0x01,             // num_elements = 1
                0x00, 0x00, 0x00, 0x02,             // name "a" BufStr prefix = 1 + 1
                (byte)'a',
                0x00, 0x00, 0x00, 0x02,             // type = STR (2)
                0x00, 0x00, 0x00, 0x01,             // num_value = 1
                0x00, 0x00, 0x00, 0x02,             // STR value length = 2 (NO +1)
                (byte)'h', (byte)'i',
            };
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void ByteLayout_UniStrElement_HasPlusOnePrefixAndTrailingNul()
        {
            // VALUE_UNISTR: prefix = utf8len + 1, payload = utf8 bytes + trailing NUL.
            byte[] actual = new Pack().SetUniStr("a", "hi").ToBytes();
            byte[] expected =
            {
                0x00, 0x00, 0x00, 0x01,             // num_elements = 1
                0x00, 0x00, 0x00, 0x02,             // name "a" BufStr prefix = 1 + 1
                (byte)'a',
                0x00, 0x00, 0x00, 0x03,             // type = UNISTR (3)
                0x00, 0x00, 0x00, 0x01,             // num_value = 1
                0x00, 0x00, 0x00, 0x03,             // UNISTR length = utf8(2) + 1
                (byte)'h', (byte)'i', 0x00,         // utf8 bytes + trailing NUL
            };
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void ByteLayout_Int64Element_IsBigEndian8Bytes()
        {
            byte[] actual = new Pack().SetInt64("v", 0x1122334455667788ul).ToBytes();
            byte[] expected =
            {
                0x00, 0x00, 0x00, 0x01,             // num_elements = 1
                0x00, 0x00, 0x00, 0x02,             // name "v" BufStr prefix
                (byte)'v',
                0x00, 0x00, 0x00, 0x04,             // type = INT64 (4)
                0x00, 0x00, 0x00, 0x01,             // num_value = 1
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // big-endian u64
            };
            Assert.Equal(expected, actual);
        }

        // ---- Hand-built hello / login field PACKs (realistic protocol shapes) ------------------------

        [Fact]
        public void ByteLayout_HelloPack_MatchesHandBuilt()
        {
            // Server "hello" PACK: hello(STR) + version(INT) + build(INT) + random(DATA 20).
            byte[] random = new byte[20];
            for (int i = 0; i < random.Length; i++) random[i] = (byte)(0xA0 + i);

            var pack = new Pack()
                .SetStr("hello", "softether")
                .SetInt("version", 441u)
                .SetInt("build", 9772u)
                .SetData("random", random);

            byte[] actual = pack.ToBytes();
            byte[] expected = BuildHelloExpected(random);
            Assert.Equal(expected, actual);

            // And it round-trips.
            Pack parsed = Pack.Parse(actual);
            Assert.Equal("softether", parsed.GetStr("hello"));
            Assert.Equal(441u, parsed.GetInt("version"));
            Assert.Equal(9772u, parsed.GetInt("build"));
            Assert.Equal(random, parsed.GetData("random"));
        }

        [Fact]
        public void LoginPack_RoundTrips_WithSha0SecurePassword()
        {
            // login fields per spec doc 07: method/hubname/username/authtype + secure_password(DATA 20) + session params.
            // SecurePassword = Sha0( Sha0(password || UPPER(username))[20] || server_random[20] ).
            const string password = "P@ssw0rd";
            const string username = "alice";
            byte[] serverRandom = new byte[20];
            for (int i = 0; i < serverRandom.Length; i++) serverRandom[i] = (byte)(i + 1);

            byte[] hashedPassword = Sha0.Hash(Concat(
                Encoding.ASCII.GetBytes(password),
                Encoding.ASCII.GetBytes(username.ToUpperInvariant())));
            byte[] securePassword = Sha0.Hash(Concat(hashedPassword, serverRandom));

            var pack = new Pack()
                .SetStr("method", "login")
                .SetStr("hubname", "DEFAULT")
                .SetStr("username", username)
                .SetInt("authtype", 2u) // password auth
                .SetData("secure_password", securePassword)
                .SetInt("max_connection", 8u)
                .SetBool("use_encrypt", true)
                .SetBool("use_compress", false)
                .SetBool("half_connection", false)
                .SetData("unique_id", Enumerable.Repeat((byte)0x5A, 16).ToArray());

            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.Equal("login", parsed.GetStr("method"));
            Assert.Equal("DEFAULT", parsed.GetStr("hubname"));
            Assert.Equal(username, parsed.GetStr("username"));
            Assert.Equal(2u, parsed.GetInt("authtype"));
            Assert.Equal(20, parsed.GetData("secure_password")!.Length);
            Assert.Equal(securePassword, parsed.GetData("secure_password"));
            Assert.Equal(8u, parsed.GetInt("max_connection"));
            Assert.True(parsed.GetBool("use_encrypt"));
            Assert.False(parsed.GetBool("half_connection"));
            Assert.Equal(16, parsed.GetData("unique_id")!.Length);
        }

        // ---- Malformed input rejection ---------------------------------------------------------------

        [Fact]
        public void Parse_Underrun_Throws()
        {
            byte[] truncated = { 0x00, 0x00, 0x00, 0x01 }; // claims 1 element, no element data
            Assert.Throws<FormatException>(() => Pack.Parse(truncated));
        }

        [Fact]
        public void Parse_ElementCountOverLimit_Throws()
        {
            byte[] buf = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(buf, (uint)PackConstants.MaxElementCount + 1);
            Assert.Throws<FormatException>(() => Pack.Parse(buf));
        }

        [Fact]
        public void Parse_DuplicateName_Throws()
        {
            // Two elements both named "x" — build by hand because the Pack API forbids duplicates on the Set side.
            var writer = new PackBufferWriter();
            writer.WriteUInt32(2); // num_elements
            for (int i = 0; i < 2; i++)
            {
                writer.WriteBufStr("x", Encoding.ASCII);
                writer.WriteUInt32((uint)PackValueType.Int);
                writer.WriteUInt32(1);
                writer.WriteUInt32((uint)i);
            }
            Assert.Throws<FormatException>(() => Pack.Parse(writer.ToArray()));
        }

        // ---- Multi-element ordering preserved --------------------------------------------------------

        [Fact]
        public void MultipleElements_PreserveInsertionOrder()
        {
            var pack = new Pack()
                .SetStr("first", "1")
                .SetInt("second", 2u)
                .SetData("third", new byte[] { 3 });
            Pack parsed = Pack.Parse(pack.ToBytes());
            Assert.Equal(3, parsed.Count);
            Assert.Equal("first", parsed.Elements[0].Name);
            Assert.Equal("second", parsed.Elements[1].Name);
            Assert.Equal("third", parsed.Elements[2].Name);
        }

        static byte[] BuildHelloExpected(byte[] random)
        {
            var w = new PackBufferWriter();
            w.WriteUInt32(4); // num_elements

            WriteName(w, "hello"); w.WriteUInt32((uint)PackValueType.Str); w.WriteUInt32(1);
            byte[] hello = Encoding.ASCII.GetBytes("softether");
            w.WriteUInt32((uint)hello.Length); w.WriteBytes(hello);

            WriteName(w, "version"); w.WriteUInt32((uint)PackValueType.Int); w.WriteUInt32(1); w.WriteUInt32(441);
            WriteName(w, "build"); w.WriteUInt32((uint)PackValueType.Int); w.WriteUInt32(1); w.WriteUInt32(9772);

            WriteName(w, "random"); w.WriteUInt32((uint)PackValueType.Data); w.WriteUInt32(1);
            w.WriteUInt32((uint)random.Length); w.WriteBytes(random);

            return w.ToArray();
        }

        static void WriteName(PackBufferWriter w, string name) => w.WriteBufStr(name, Encoding.ASCII);

        static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }
    }
}
