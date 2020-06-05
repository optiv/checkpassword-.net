using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using System.Threading.Tasks;

using OptivAppsec.CheckPassword;

namespace CheckPasswordUnitTests
{
    [TestClass]
    public class UnitTest_Basic
    {
        [TestMethod]
        public void TestSHA1()
        {
            Assert.AreEqual(HIBPClient.Sha1Hex("A test string"), "2F960C7436AE0BBD409C522D3FA081D05B077395");
            Assert.AreEqual(HIBPClient.Sha1Hex("Password1"), "70CCD9007338D6D81DD3B6271621B9CF9A97EA00");
            Assert.AreEqual(HIBPClient.Sha1Hex("Optiv"), "8C283ADEBA830D3D086807FE53EA168B4EC320D2");
            Assert.AreEqual(HIBPClient.Sha1Hex("ey5IDR3l5Lp75ocNRcQn"), "5EC59EFD9AD699D6130E07AD33DDAC2A1D04F4F8");
            Assert.AreEqual(HIBPClient.Sha1Hex("diugtVhokeQykrWe3ZUe"), "47DE7C93AB6BD5E80A3AFE37E57FF51E1A63D9C9");

            Assert.AreEqual(HIBPClient.Sha1Hex("こんにちは", Encoding.UTF7), "7FE1D05E094B3694F830DA9339CF6D5CCB64A56E");
        }

        [TestMethod]
        public void TestCheck()
        {
            HIBPClient client = new HIBPClient(new HIBPClientSettings("Testing API Library") );
            // These may need to be periodicly updated
            Assert.IsFalse(client.Check("password"));
            Assert.IsFalse(client.Check("Password1"));
            Assert.IsFalse(client.Check("Optiv"));
            Assert.IsTrue(client.Check("ey5IDR3l5Lp75ocNRcQn"));
            Assert.IsTrue(client.Check("diugtVhokeQykrWe3ZUe"));

        }

        [TestMethod]
        public void TestCheckAsync()
        {
            HIBPClient client = new HIBPClient(new HIBPClientSettings("Testing API Library"));
            Task<bool> test_password = client.CheckAsync("password");
            Task<bool> test_Password1 = client.CheckAsync("Password1");
            Task<bool> test_optiv = client.CheckAsync("optiv");
            Task<bool> test_random1 = client.CheckAsync("ey5IDR3l5Lp75ocNRcQn");
            Task<bool> test_random2 = client.CheckAsync("ey5IDR3l5Lp75ocNRcQn");


            Assert.IsFalse(test_password.Result);
            Assert.IsFalse(test_Password1.Result);
            Assert.IsFalse(test_optiv.Result);
            Assert.IsTrue(test_random1.Result);
            Assert.IsTrue(test_random2.Result);
        }

    }
}
