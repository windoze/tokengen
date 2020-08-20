using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CommandLine;
using Microsoft.Identity.Client;
using Newtonsoft.Json;

namespace tokengen
{
    // ReSharper disable once ClassNeverInstantiated.Global
    class Program
    {
        // ReSharper disable once ClassNeverInstantiated.Global
        public class Options
        {
            [Option('p', "profile", Required = false, Default = "", HelpText = "Select the profile to use.")]
            public string Profile { get; set; }

            [Option('c', "client-id", Required = false, Default = "", HelpText = "AAD App Client ID.")]
            public string ClientId { get; set; }

            [Option('s', "secret", Required = false, Default = "", HelpText = "AAD App Secret.")]
            public string Secret { get; set; }

            [Option('t', "tenant", Required = false, Default = "", HelpText = "AAD App Tenant.")]
            public string Tenant { get; set; }

            [Option('a', "authority", Required = false, Default = "",
                HelpText = "Authority.")]
            public string Authority { get; set; }

            [Option('r', "resource", Required = false, Default = "", HelpText = "Resource(Scope).")]
            public string Resource { get; set; }

            [Option('y', "type", Required = false, Default = "access",
                HelpText = "Token type, can be 'access' or 'id'.")]
            public string Type { get; set; }

            [Option('f', "format", Required = false, Default = "header",
                HelpText = "Output header format, can be 'header', 'bearer', or 'raw'.")]
            public string Format { get; set; }
        }

        public class Profile
        {
            public string DefaultProfile { get; set; }
            public Config[] Profiles { get; set; }
        }

        public class Config
        {
            public string Name { get; set; } = "";
            public string ClientId { get; set; } = "";
            public string Secret { get; set; } = "";
            public string Tenant { get; set; } = "";
            public string Authority { get; set; } = "https://login.microsoftonline.com";
            public string Resource { get; set; } = "";

            public Config()
            {
            }

            public Config(Options options)
            {
                if (!string.IsNullOrWhiteSpace(options.Profile))
                {
                    ReadProfile(options.Profile);
                }

                if (!string.IsNullOrWhiteSpace(options.ClientId)) this.ClientId = options.ClientId;
                if (!string.IsNullOrWhiteSpace(options.Secret)) this.Secret = options.Secret;
                if (!string.IsNullOrWhiteSpace(options.Tenant)) this.Tenant = options.Tenant;
                if (!string.IsNullOrWhiteSpace(options.Authority)) this.Authority = options.Authority;
                if (!string.IsNullOrWhiteSpace(options.Resource)) this.Resource = options.Resource;

                if (IsEmpty())
                {
                    if (string.IsNullOrWhiteSpace(options.Profile))
                    {
                        ReadProfile("");
                    }
                }
            }

            public bool IsEmpty()
            {
                return string.IsNullOrWhiteSpace(ClientId)
                       && string.IsNullOrWhiteSpace(Secret)
                       && string.IsNullOrWhiteSpace(Tenant)
                       && string.IsNullOrWhiteSpace(Resource);
            }

            private void ReadProfile(string profile)
            {
                var configFileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".tokengen_config.json");
                string content;
                try
                {
                    content = File.ReadAllText(configFileName);
                }
                catch (FileNotFoundException e)
                {
                    return;
                }

                var profiles = JsonConvert.DeserializeObject<Profile>(content);
                if (string.IsNullOrWhiteSpace(profile))
                {
                    profile = profiles.DefaultProfile;
                }

                if (string.IsNullOrWhiteSpace(profile))
                {
                    profile = "DEFAULT";
                }

                var configs = profiles.Profiles;
                var config = configs.FirstOrDefault((c) => c.Name == profile);
                if (config == null)
                {
                    Console.Error.WriteLine($"ERROR: Unknown profile '{profile}'.");
                    throw new InvalidDataException();
                }

                if (!string.IsNullOrWhiteSpace(config.Name)) this.Name = config.Name;
                if (!string.IsNullOrWhiteSpace(config.ClientId)) this.ClientId = config.ClientId;
                if (!string.IsNullOrWhiteSpace(config.Secret)) this.Secret = config.Secret;
                if (!string.IsNullOrWhiteSpace(config.Tenant)) this.Tenant = config.Tenant;
                if (!string.IsNullOrWhiteSpace(config.Authority)) this.Authority = config.Authority;
                if (!string.IsNullOrWhiteSpace(config.Resource)) this.Resource = config.Resource;
            }
        }

        public class CacheEntry
        {
            public string IdToken { get; set; }
            public string AccessToken { get; set; }
            public DateTimeOffset Expiration { get; set; }
        }

        private static IDictionary<string, CacheEntry> tokenCache;

        private static void LoadCache()
        {
            var cacheFileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".tokengen_cache.json");
            string content;
            try
            {
                content = File.ReadAllText(cacheFileName);
            }
            catch (FileNotFoundException e)
            {
                content = "{}";
            }

            tokenCache = JsonConvert.DeserializeObject<Dictionary<string, CacheEntry>>(content) ?? new Dictionary<string, CacheEntry>();
        }

        private static void SaveCache()
        {
            var cacheFileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".tokengen_cache.json");
            foreach (var (key, value) in tokenCache)
            {
                if (value.Expiration - DateTimeOffset.UtcNow <= TimeSpan.FromMinutes(5))
                {
                    tokenCache.Remove(key);
                }
            }

            using var file = File.CreateText(cacheFileName);
            var serializer = new JsonSerializer();
            serializer.Serialize(file, tokenCache);
        }

        private static async Task<string> GetToken(Options options)
        {
            var config = new Config(options);
            if (config.IsEmpty())
            {
                await Console.Error.WriteLineAsync($"ERROR: Missing command line arguments.");
                throw new InvalidDataException();
            }

            LoadCache();

            var key = $"{config.ClientId}\t{config.Tenant}\t{config.Authority}\t{config.Resource}";
            if (tokenCache != null && tokenCache.ContainsKey(key))
            {
                // Check if the token is expired
                var expiration = tokenCache[key].Expiration;
                if (expiration - DateTimeOffset.UtcNow > TimeSpan.FromMinutes(5))
                {
                    // The token is still valid in next 5 minutes
                    switch (options.Type)
                    {
                        case "id":
                            return tokenCache[key].IdToken;
                        case "access":
                            return tokenCache[key].AccessToken;
                        default:
                            await Console.Error.WriteLineAsync($"ERROR: Unknown token type '{options.Type}'.");
                            throw new InvalidDataException();
                    }
                }
            }

            var app = ConfidentialClientApplicationBuilder
                .Create(config.ClientId)
                .WithClientSecret(config.Secret)
                .WithAuthority(config.Authority, config.Tenant, false)
                .Build();
            var result = await app.AcquireTokenForClient(new string[] { $"{config.Resource}/.default" })
                .ExecuteAsync();
            
            tokenCache[key] = new CacheEntry
            {
                IdToken = result.IdToken,
                AccessToken = result.AccessToken,
                Expiration = result.IsExtendedLifeTimeToken ? result.ExtendedExpiresOn : result.ExpiresOn
            };
            SaveCache();

            switch (options.Type)
            {
                case "id":
                    return result.IdToken;
                case "access":
                    return result.AccessToken;
                default:
                    await Console.Error.WriteLineAsync($"ERROR: Unknown token type '{options.Type}'.");
                    throw new InvalidDataException();
            }
        }

        private static async Task OutputToken(Options options)
        {
            var token = await GetToken(options);
            switch (options.Format)
            {
                case "raw":
                    Console.WriteLine(token);
                    break;
                case "bearer":
                    Console.WriteLine($"Bearer {token}");
                    break;
                case "header":
                    Console.WriteLine($"Authorization: Bearer {token}");
                    break;
                default:
                    await Console.Error.WriteLineAsync($"ERROR: Unknown format '{options.Format}'.");
                    throw new InvalidDataException();
            }
        }

        public static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed<Options>(o => { OutputToken(o).Wait(); });
        }
    }
}