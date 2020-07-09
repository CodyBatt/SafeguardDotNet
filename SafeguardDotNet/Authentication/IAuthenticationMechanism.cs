﻿using System;
using System.Net.Security;
using System.Security;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal interface IAuthenticationMechanism : IDisposable, ICloneable
    {
        string Id { get;  }

        string NetworkAddress { get; }

        int ApiVersion { get; }

        bool IgnoreSsl { get; }

        RemoteCertificateValidationCallback ValidationCallback { get; }

        bool IsAnonymous { get; }

        bool HasAccessToken();

        void ClearAccessToken();

        SecureString GetAccessToken();

        int GetAccessTokenLifetimeRemaining();

        void RefreshAccessToken();
    }
}
