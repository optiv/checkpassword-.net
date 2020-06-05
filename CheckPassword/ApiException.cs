using System;
using System.Collections.Generic;
using System.Text;

namespace OptivAppsec.CheckPassword
{
    public class ApiException : Exception
    {
        public ApiException()
        {
        }

        public ApiException(string message) : base(message)
        {
        }

        public ApiException(string message, Exception ex) : base(message, ex)
        {
        }
    }
}
