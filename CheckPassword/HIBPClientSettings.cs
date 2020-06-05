using System;
using System.Collections.Generic;
using System.Text;

namespace OptivAppsec.CheckPassword
{
    public class HIBPClientSettings
    {
        /// <summary>
        /// The API requires (per the Acceptable Use policy) that API clients include an
        /// identifying User Agent header. This should be unique to each application,
        /// and may be used to throttle requests. Using a "generic" value may mean your
        /// requests are more aggressively rate limited. There is no other guidance for
        /// this User Agent string, so "Optiv Website" is an acceptble value, for example.
        /// </summary>
        public string UserAgent { get; set; } = null;

        private int retries = 2;
        /// <summary>
        /// Number of times to retry a request if a 429 Too Many Requests is received.
        /// Set to 0 to disable retrying.
        /// </summary>
        public int Retries
        {
            get
            {
                return retries;
            }
            set
            {
                if(value < 0)
                {
                    throw new ArgumentOutOfRangeException("Retries should be 0 or greater");
                }
                retries = value;
            }
        }

        // seconds
        private double maxWait = 2.0;
        /// <summary>
        /// Maximum time to wait before retrying. In order to abide by the API's acceptable
        /// use, the library will not make another request if the wait time is longer than
        /// this value. (It will never wait less than what the API asks for.)
        /// </summary>
        public double MaxWait
        {
            get
            {
                return maxWait;
            }
            set
            {
                if (value < 0)
                {
                    throw new ArgumentOutOfRangeException("Max Wait should be 0 or greater");
                }
            }
        }

        private TimeSpan timeout = new TimeSpan(0, 0, 5);
        /// <summary>
        /// How long to wait for a response to any request before giving up
        /// </summary>
        public double Timeout
        {
            get
            {
                return timeout.TotalSeconds;
            }
            set
            {
                if(value <= 0)
                {
                    throw new ArgumentOutOfRangeException("Timeout must be greater than 0");
                }
                // We need to turn this double into a TimeSpan. We will allow millisecond
                // precision because anything tighter is pretty silly for network requests.
                int seconds = (int)Math.Truncate(value);
                int msec = (int)Math.Truncate((value - seconds) * 1000);
                timeout = new TimeSpan(0, 0, 0, seconds, msec);
            }
        }

        /// <summary>
        /// Returns the timeout as a timespan for use with HttpClient objects
        /// </summary>
        /// <returns></returns>
        public TimeSpan TimeoutSpan
        {
            get
            {
                return timeout;
            }
        }

        /// <summary>
        /// Indicates whether or not to expose the version number of the library in
        /// the User Agent header.
        /// </summary>
        public bool HideClientVersion { get; set; } = true;

        /// <summary>
        /// Your API key, if you have one. This library does not need one, as the password checking
        /// endpoint is free. However, if you do have one, you may provide it if you wish.
        /// </summary>
        public string ApiKey { get; set; } = null;

        private int maxResponseBufferSize = 512000;
        public int MaxResponseContentBufferSize
        {
            get
            {
                return maxResponseBufferSize;
            }
            set
            {
                if(value <= 0)
                {
                    throw new ArgumentOutOfRangeException("MaxResponseContentBufferSize must be greater than 0");
                }
                maxResponseBufferSize = value;
            }
        }

        /// <summary>
        /// Constructor for HIBPClientSettings object. All settings except UserAgent have a
        /// default value which can be safely used. Per the API's accetable user policy,
        /// UserAgents should identify the app that's using the API, so this library can't
        /// come up with a good default. Example: "Optiv Website"
        /// </summary>
        /// <param name="userAgent">User Agent string, identify applicaiton.</param>
        public HIBPClientSettings(string userAgent)
        {
            UserAgent = userAgent;
        }
    }
}
