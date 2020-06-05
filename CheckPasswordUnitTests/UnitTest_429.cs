using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using System.Threading.Tasks;

using OptivAppsec.CheckPassword;

namespace CheckPasswordUnitTests
{
    [TestClass]
    public class UnitTest_429
    {

        [TestMethod]
        public void Test429Response_RUN_MANUALLY()
        {
            // With Retries = 0, this should throw an error as soon as we hit a 429
            // That's correct handling for Retries = 0
            HIBPClient client = new HIBPClient(new HIBPClientSettings("Testing API Library") { Retries = 0 });

            // I'm not comfortable throwing while(true) on this, but I haven't acually triggered a 429 yet...
            for (int i = 0; i < 10000; i++)
            {
                Assert.IsFalse(client.Check("password"));
            }
            
        }


    }
}
