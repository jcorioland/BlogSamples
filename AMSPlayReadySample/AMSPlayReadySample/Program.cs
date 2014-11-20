using Microsoft.WindowsAzure.MediaServices.Client;
using Microsoft.WindowsAzure.MediaServices.Client.ContentKeyAuthorization;
using Microsoft.WindowsAzure.MediaServices.Client.DynamicEncryption;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AMSPlayReadySample
{
    class Program
    {
        static void Main(string[] args)
        {
            string videoFilePath = @"YOUR FILE TO UPLOAD";

            Uri issuerName = new Uri(ConfigurationManager.AppSettings["IssuerName"]);
            Uri scope = new Uri(ConfigurationManager.AppSettings["Scope"]);
            byte[] signingKey = Convert.FromBase64String(ConfigurationManager.AppSettings["SigningKey"]);

            string mediaServiceName = ConfigurationManager.AppSettings["MediaServiceName"];
            string mediaServiceKey = ConfigurationManager.AppSettings["MediaServiceKey"];

            var context = new CloudMediaContext(mediaServiceName, mediaServiceKey);

            var asset = context.Assets.CreateFromFile(videoFilePath, AssetCreationOptions.None, (sender, progressChanged) =>
            {
                Console.WriteLine("{0} of {1} bytes uploaded", progressChanged.BytesUploaded, progressChanged.TotalBytes);
            });

            IJob job = context.Jobs.CreateWithSingleTask(
                MediaProcessorNames.AzureMediaEncoder,
                MediaEncoderTaskPresetStrings.H264AdaptiveBitrateMP4Set720p,
                asset,
                "Adaptive Bitrate MP4",
                AssetCreationOptions.None);

            job.Submit();
            job = job.StartExecutionProgressTask(j =>
            {
                Console.WriteLine("Job state : {0}", j.State);
                Console.WriteLine("Job progress: {0:0.##}%", j.GetOverallProgress());
            }, CancellationToken.None).Result;

            var outputAsset = job.OutputMediaAssets.FirstOrDefault();

            if (outputAsset != null)
            {
                ConfigurePlayReadyDynamicEncryptionAsync(context, outputAsset, issuerName, scope, signingKey).Wait();

                var accessPolicy = context.AccessPolicies
                .Where(a => a.Name == "catchup_policy")
                .AsEnumerable()
                .FirstOrDefault();

                if (accessPolicy == null)
                {
                    accessPolicy = context.AccessPolicies
                        .Create("catchup_policy", TimeSpan.FromDays(100 * 365), AccessPermissions.Read);
                }

                // remove existing locators
                foreach (var existingLocator in outputAsset.Locators.ToList())
                {
                    existingLocator.Delete();
                }

                var locator = context.Locators
                    .CreateLocator(LocatorType.OnDemandOrigin, outputAsset, accessPolicy);

                Debug.WriteLine(locator.GetSmoothStreamingUri());
            }

            var swt = new SimpleWebToken(ConfigurationManager.AppSettings["SigningKey"], TimeSpan.FromMinutes(10));
            swt.Audience = scope.ToString();
            swt.Issuer = issuerName.ToString();

            string token = swt.ToString();

            Debug.WriteLine(token);
        }

        private static async Task ConfigurePlayReadyDynamicEncryptionAsync(
            CloudMediaContext cloudMediaContext,
            IAsset outputAsset,
            Uri issuerName,
            Uri scope,
            byte[] signingKey)
        {
            IContentKey contentKey = null;
            var assetContentKeys = outputAsset.ContentKeys
                .Where(c => c.ContentKeyType == ContentKeyType.CommonEncryption);

            if (!assetContentKeys.Any())
            {
                contentKey = await CreateCommonTypeContentKeyAsync(outputAsset, cloudMediaContext);
            }
            else
            {
                contentKey = assetContentKeys.First();
            }

            var tokenRestrictions = GetTokenRestrictions(
                "My STS Token Restrictions",
                issuerName,
                scope,
                signingKey);

            var playReadyLicenseTemplate = ConfigurePlayReadyLicenseTemplate();

            IContentKeyAuthorizationPolicyOption policyOption = await
                cloudMediaContext.ContentKeyAuthorizationPolicyOptions.CreateAsync(
                "Option with Token Restriction",
                ContentKeyDeliveryType.PlayReadyLicense,
                tokenRestrictions,
                playReadyLicenseTemplate);

            IContentKeyAuthorizationPolicy policy = await cloudMediaContext
                .ContentKeyAuthorizationPolicies
                .CreateAsync("ACS Authorization Policy");

            policy.Options.Add(policyOption);
            await policy.UpdateAsync();

            contentKey.AuthorizationPolicyId = policy.Id;
            await contentKey.UpdateAsync();

            var licenseAcquisitionUrl = await contentKey.GetKeyDeliveryUrlAsync(ContentKeyDeliveryType.PlayReadyLicense);
            string strLicenseAcquisitionUrl = System.Security.SecurityElement.Escape(licenseAcquisitionUrl.ToString());

            Dictionary<AssetDeliveryPolicyConfigurationKey, string> assetDeliveryPolicyConfiguration =
                new Dictionary<AssetDeliveryPolicyConfigurationKey, string>
                {
                    {
                        AssetDeliveryPolicyConfigurationKey.PlayReadyLicenseAcquisitionUrl, strLicenseAcquisitionUrl
                    },
                };

            var assetDeliveryPolicy = await cloudMediaContext.AssetDeliveryPolicies.CreateAsync(
                "PlayReady Delivery Policy",
                AssetDeliveryPolicyType.DynamicCommonEncryption,
                AssetDeliveryProtocol.SmoothStreaming,
                assetDeliveryPolicyConfiguration);

            outputAsset.DeliveryPolicies.Add(assetDeliveryPolicy);
            await outputAsset.UpdateAsync();

        }

        private static async Task<IContentKey> CreateCommonTypeContentKeyAsync(IAsset asset, CloudMediaContext _context)
        {
            // Create envelope encryption content key
            Guid keyId = Guid.NewGuid();
            byte[] contentKey = GetRandomBuffer(16);

            IContentKey key = await _context.ContentKeys.CreateAsync(
                                    keyId,
                                    contentKey,
                                    "ContentKey CENC",
                                    ContentKeyType.CommonEncryption);

            // Associate the key with the asset.
            asset.ContentKeys.Add(key);

            return key;
        }

        private static byte[] GetRandomBuffer(int size)
        {
            byte[] randomBytes = new byte[size];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
            }

            return randomBytes;
        }

        private static List<ContentKeyAuthorizationPolicyRestriction> GetTokenRestrictions(string name, Uri issuer, Uri scope, byte[] signingKey)
        {
            TokenRestrictionTemplate tokenTemplate = new TokenRestrictionTemplate();
            tokenTemplate.Issuer = issuer;
            tokenTemplate.Audience = scope;
            tokenTemplate.PrimaryVerificationKey = new SymmetricVerificationKey(signingKey);

            string requirements = TokenRestrictionTemplateSerializer.Serialize(tokenTemplate);

            List<ContentKeyAuthorizationPolicyRestriction> restrictions = new List<ContentKeyAuthorizationPolicyRestriction>()
                {
                    new ContentKeyAuthorizationPolicyRestriction()
                        { 
                            KeyRestrictionType = (int)ContentKeyRestrictionType.TokenRestricted, 
                            Requirements = requirements, 
                            Name = name
                        }
                };

            return restrictions;
        }

        private static string ConfigurePlayReadyLicenseTemplate()
        {
            PlayReadyLicenseResponseTemplate responseTemplate = new PlayReadyLicenseResponseTemplate();
            PlayReadyLicenseTemplate licenseTemplate = new PlayReadyLicenseTemplate();
            licenseTemplate.PlayRight.AllowPassingVideoContentToUnknownOutput = UnknownOutputPassingOption.Allowed;
            responseTemplate.LicenseTemplates.Add(licenseTemplate);

            return MediaServicesLicenseTemplateSerializer.Serialize(responseTemplate);
        }
    }
}
