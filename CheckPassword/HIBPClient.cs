using System;
using System.Text;
using System.Security.Cryptography;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace OptivAppsec.CheckPassword
{

    /// <summary>
    /// Static class for checking passwords against the PwndPasswords API
    /// </summary>
    public class HIBPClient : IHIBPClient
    {
        private static string version = "1.0";

        private static readonly string baseUrlv3 = "https://api.pwnedpasswords.com/range/";

        private static readonly string userAgentPostfix = "Optiv API Client";

        // This value is recommended by NIST S.P. 800-63. Applications can require longer
        // passwords, but we should not consider anything shorter to be "secure".
        // Callers should consider including a maximum length of 64-128 characters, which
        // reduces the risk of Denial of Service attacks when secure password hashing is used
        private static readonly int minLength = 8;

        private HIBPClientSettings settings;
        private HttpClient client;

        /// <summary>
        /// Creates HIBPClient object with the given settings. 
        /// </summary>
        /// <param name="settings">Settings, including required User-Agent value</param>
        public HIBPClient(HIBPClientSettings settings)
        {
            this.settings = settings;

            client = new HttpClient();
            client.MaxResponseContentBufferSize = settings.MaxResponseContentBufferSize;
            client.Timeout = settings.TimeoutSpan;

            string userAgent;
            if (settings.HideClientVersion) {
                userAgent = string.Format("{0} ({1} {2})", settings.UserAgent, userAgentPostfix, version);
            }
            else
            {
                userAgent = string.Format("{0} ({1})", settings.UserAgent, userAgentPostfix);
            }

            client.DefaultRequestHeaders.Add("User-Agent", userAgent);

            if(settings.ApiKey != null)
            {
                client.DefaultRequestHeaders.Add("hibp-api-key", settings.ApiKey);
            }

        }

        /// <summary>
        /// Helper method to make sure the user's password is long enough. External
        /// callers are free to make more restrictive tests.
        /// </summary>
        /// <param name="password">Password to check</param>
        /// <returns>True if long enough, false otherwise</returns>
        private static bool CheckLength(string password)
        {
            return password.Length >= minLength;
        }


        /* Synchronous methods */

        /// <summary>
        /// Checks the provided password against the latest version of the API. Uses the system's default
        /// TLS configuration, which should be secure if the system is up to date.
        /// </summary>
        /// <param name="password">Password to check against the API</param>
        /// <returns>True when the password hasn't been seen in previous breaches ("is secure"), false if it has.</returns>
        public bool Check(string password)
        {
            return CheckV3(password).Result;

        }


        /* Asynchronous methods */

        /// <summary>
        /// Checks the provided password against the latest version of the API, exposing the asynchronous
        /// nature of the HTTPS request. Uses the system's default TLS configuration, which should be secure
        /// if the system is up to date.
        /// 
        /// </summary>
        /// <param name="password">Password to check against the API</param>
        /// <returns>True when the password hasn't been seen in previous breaches ("is secure"), false if it has.</returns>
        public async Task<bool> CheckAsync(string password)
        {
            return await CheckV3(password);
        }

        /// <summary>
        /// Checks V3 of the API to determine if the password has been seen before and is known to attackers.
        /// 
        /// This version of the API accepts the first 5 hexadecimal characters from the password's SHA-1 hash.
        /// While SHA-1 is not a secure choice of password hash, only revealing the first is secure as there are
        /// 2**124 possible hashes which could match the information sent to the server. In the event the API is
        /// compromised, this is still sufficiently large that attackers cannot guess what the original password
        /// was via bute force attacks.
        /// 
        /// The server will response with hex hash values (less the first 5 characters) and a number indicating
        /// how many breaches this password was been recovered from. This version of the library discards the
        /// latter information. By comparing our hash to each response from the API, we can determine if this
        /// password hash been seen before without disclosing the password to the API.
        /// </summary>
        /// <param name="password">Password to check</param>
        /// <returns></returns>
        private async Task<bool> CheckV3(string password)
        {
            if (!CheckLength(password))
                return false;

            string hash = Sha1Hex(password);
            string hashStart = hash.Substring(0, 5);
            string hashEnd = hash.Substring(5);


            HttpResponseMessage response = await GetPasswordHashesAPI(hashStart);

            string responseBody = await response.Content.ReadAsStringAsync();

            // StringReader handles different line endings (\r\n, \n, \r) automagically
            using (System.IO.StringReader reader = new System.IO.StringReader(responseBody))
            {
                string line;
                while ( (line = reader.ReadLine()) != null){

                    string[] pieces = line.Split(':');
                    if (pieces.Length != 2)
                    {
                        // This API spec says every line should be HEXHASH:number
                        // If it's not, something has gone very wrong.
                        throw new ApiException("Malformed response from API");
                    }

                    if (hashEnd.Equals(pieces[0]))
                    {
                        // Our hash matches the returned hash, so this password is known
                        return false;
                    }
                }
            }

            // Can only get here if we never found a match, so the password is unknown
            return true;
        }

        /// <summary>
        /// A helper method to make requests to the API. Handles retries and 429 Too Many Requests
        /// </summary>
        /// <param name="hashStart">First 5 hex characters from SHA-1 hash to test</param>
        /// <returns>string with applications response</returns>
        private async Task<HttpResponseMessage> GetPasswordHashesAPI(string hashStart)
        {
            HttpResponseMessage response;

            // Our initial try is not a retry, so we need to try
            // Retries + 1 times total.
            for (int i = 0; i < settings.Retries + 1; i++)
            {
                
                try
                {
                    response = await client.GetAsync(new Uri(baseUrlv3) + hashStart);
                }
                catch (HttpRequestException ex)
                {
                    // There's nothing logical we can if this fails, so:
                    throw new ApiException("Problem making a request to the API", ex);
                }
                catch (TaskCanceledException ex)
                {
                    throw new ApiException("The API failed to response before the timeout", ex);
                }

                
                if (response.IsSuccessStatusCode)
                {
                    return response;
                }
                else
                {
                    // .NET Standard doesn't have 429 in the enum, so we'll cast to int
                    int statusCode = (int)response.StatusCode;
                    if (statusCode == 429)
                    {
                        // If this is the case, the API should **always** give us back one (and
                        // only one) retry-after header, an integer number of seconds.
                        var headers = response.Headers;
                        int retryAfter = -1;
                        foreach (string headerValue in headers.GetValues("retry-after"))
                        {
                            try
                            {
                                retryAfter = int.Parse(headerValue);
                            }
                            catch (Exception)
                            {
                                // We will handle all error cases below, not here.
                                // Any unparsable value means we need to give up.
                            }
                        }

                        // Handles:
                        // * no "retry-after" header found
                        // * "retry-after" not parsable as int
                        if (retryAfter < 0)
                        {
                            throw new ApiException("API provided invalid or missing 'retry-after' header on 429 response");
                        }

                        // Sleep value expects milliseconds
                        Thread.Sleep(retryAfter * 1000);
                    }
                    else
                    {
                        throw new ApiException(string.Format("Received unexpected status code {0} from API", statusCode));
                    }
                }
            }

            throw new ApiException(string.Format("Failed to receive 200 resonse from API, exhausted {0} retries", settings.Retries));
        }

        public static string Sha1Hex(string message)
        {
            SHA1 sha = new SHA1CryptoServiceProvider();
            byte[] result = sha.ComputeHash(Encoding.UTF8.GetBytes(message));

            StringBuilder hex = new StringBuilder(result.Length * 2);
            foreach (byte b in result)
            {
                hex.AppendFormat("{0:x2}", b);
            }

            // API returns hash values using capital letters. Capitalize here
            // so that we never forget to capitalize it later.
            return hex.ToString().ToUpper();
        }
    }
}