using TqkLibrary.Vpn.Crypto;
using Xunit;

namespace TqkLibrary.Vpn.Crypto.Tests
{
    public class ModpDhGroupTests
    {
        [Theory]
        [InlineData(2, 128)]
        [InlineData(14, 256)]
        public void Dh_BothPartiesDeriveSameSecret(int groupId, int expectedSize)
        {
            ModpDhGroup group = groupId == 2 ? ModpDhGroup.Group2() : ModpDhGroup.Group14();
            Assert.Equal(groupId, group.GroupId);
            Assert.Equal(expectedSize, group.PublicValueSizeInBytes);

            byte[] aPriv = group.GeneratePrivateKey();
            byte[] aPub = group.DerivePublicValue(aPriv);
            byte[] bPriv = group.GeneratePrivateKey();
            byte[] bPub = group.DerivePublicValue(bPriv);

            Assert.Equal(expectedSize, aPub.Length);
            Assert.Equal(expectedSize, bPub.Length);

            byte[] aShared = group.DeriveSharedSecret(aPriv, bPub);
            byte[] bShared = group.DeriveSharedSecret(bPriv, aPub);

            Assert.Equal(aShared, bShared);
            // A non-trivial shared secret (not all zero).
            Assert.Contains(aShared, x => x != 0);
        }
    }
}
