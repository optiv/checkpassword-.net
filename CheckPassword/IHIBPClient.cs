using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace OptivAppsec.CheckPassword
{
    interface IHIBPClient
    {
        /// <summary>
        /// Checks the provided password against the latest version of the API.
        /// </summary>
        /// <param name="password">Password to check against the API</param>
        /// <returns>True when the password hasn't been seen in previous breaches ("is secure"), false if it has.</returns>
        bool Check(string password);

        /// <summary>
        /// Checks the provided password against the latest version of the API asynchronously
        /// 
        /// </summary>
        /// <param name="password">Password to check against the API</param>
        /// <returns>True when the password hasn't been seen in previous breaches ("is secure"), false if it has.</returns>
        Task<bool> CheckAsync(string password);

    }
}
