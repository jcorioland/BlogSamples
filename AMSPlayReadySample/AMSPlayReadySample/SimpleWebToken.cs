using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace AMSPlayReadySample
{
    /// <summary>
    /// Represents a simple web token
    /// </summary>
    public class SimpleWebToken
    {
        private static readonly DateTime epochStart = 
            new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
        
        private NameValueCollection claimsCollection;
        private byte[] signingKey = null;

        /// <summary>
        /// Initializes a new instance of the <see cref="SimpleWebToken"/> class.
        /// </summary>
        /// <param name="base64Key">The base64 key used to sign the token.</param>
        /// <param name="ttl">The time to live.</param>
        public SimpleWebToken(string base64Key, TimeSpan ttl)
        {
            TimeSpan ts = DateTime.UtcNow - epochStart + ttl;
            this.ExpiresOn = Convert.ToUInt64(ts.TotalSeconds);
            this.claimsCollection = new NameValueCollection();

            var securityKey = new InMemorySymmetricSecurityKey(Convert.FromBase64String(base64Key));
            signingKey = securityKey.GetSymmetricKey();
        }

        /// <summary>
        /// Gets or sets the issuer.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the audience.
        /// </summary>
        public string Audience { get; set; }

        /// <summary>
        /// Gets or sets the signature.
        /// </summary>
        public byte[] Signature { get; set; }

        /// <summary>
        /// Gets the expires on.
        /// </summary>
        public ulong ExpiresOn { get; private set; }

        /// <summary>
        /// Gets the claims.
        /// </summary>
        /// <value>
        /// The claims.
        /// </value>
        public IList<Claim> Claims
        {
            get
            {
                return this.claimsCollection.AllKeys
                    .SelectMany(key =>
                        this.claimsCollection[key].Split(',')
                            .Select(value => new Claim(key, value)))
                               .ToList();
            }
        }

        /// <summary>
        /// Adds the claim.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="value">The value.</param>
        public void AddClaim(string name, string value)
        {
            this.claimsCollection.Add(name, value);
        }

        /// <summary>
        /// Returns a <see cref="System.String" /> that represents this instance.
        /// </summary>
        /// <returns>
        /// A <see cref="System.String" /> that represents this instance.
        /// </returns>
        public override string ToString()
        {
            StringBuilder content = new StringBuilder();

            content.Append("Issuer=").Append(this.Issuer);

            foreach (string key in this.claimsCollection.AllKeys)
            {
                content.Append('&').Append(key)
                    .Append('=').Append(this.claimsCollection[key]);
            }

            content.Append("&ExpiresOn=").Append(this.ExpiresOn);

            if (!string.IsNullOrWhiteSpace(this.Audience))
            {
                content.Append("&Audience=").Append(this.Audience);
            }

            using (HMACSHA256 hmac = new HMACSHA256(signingKey))
            {
                byte[] signatureBytes = hmac.ComputeHash(
                    Encoding.ASCII.GetBytes(content.ToString()));

                string signature = HttpUtility.UrlEncode(
                   Convert.ToBase64String(signatureBytes));

                content.Append("&HMACSHA256=").Append(signature);
            }

            return content.ToString();
        }
    }
}
