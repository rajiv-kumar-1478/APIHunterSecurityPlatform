using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class RegistryManifestProvenanceVerifierTests
{
    private static ScanToolManifest CreateManifest(string digest) => new(
        ToolKey: "httpx",
        Version: "1.6.0",
        Description: "HTTP probing tool",
        ContainerImageRepository: "ghcr.io/projectdiscovery/httpx",
        ContainerImageReference: "ghcr.io/projectdiscovery/httpx:v1.6.0",
        ContainerImageDigest: digest,
        SupportedProfiles: new HashSet<SecurityScanProfileType> { SecurityScanProfileType.Recon },
        Capabilities: new HashSet<string> { "http.probe" },
        DiscoveredAssetTypes: new[] { "endpoint" },
        ParserVersion: "1.0",
        ManifestVersion: "1.0"
    );

    [Fact]
    public async Task VerifyManifestDigest_MatchingRegistryDigest_ReturnsVerified()
    {
        var rawPayload = "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.docker.distribution.manifest.v2+json\"}";
        var computedHash = $"sha256:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawPayload))).ToLowerInvariant()}";
        var manifest = CreateManifest(computedHash);

        var mockHandler = new MockHttpMessageHandler((req) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(rawPayload, Encoding.UTF8, "application/vnd.docker.distribution.manifest.v2+json")
            };
            response.Headers.Add("Docker-Content-Digest", computedHash);
            return response;
        });

        var client = new HttpClient(mockHandler);
        var verifier = new RegistryManifestProvenanceVerifier(client, NullLogger<RegistryManifestProvenanceVerifier>.Instance);

        var result = await verifier.VerifyManifestDigestAsync(manifest);

        Assert.True(result.IsVerified);
        Assert.Equal(computedHash, result.ResolvedDigest);
        Assert.Null(result.ErrorMessage);
    }

    [Fact]
    public async Task VerifyManifestDigest_MismatchingRegistryDigest_ReturnsFailure()
    {
        var rawPayload = "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.docker.distribution.manifest.v2+json\"}";
        var computedHash = $"sha256:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawPayload))).ToLowerInvariant()}";
        var committedDigest = "sha256:52d58be716e8fe2a592da2a3a3652985d6c71c9b68a6f3dc8e4b789ad7e2c91b";
        var manifest = CreateManifest(committedDigest);

        var mockHandler = new MockHttpMessageHandler((req) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(rawPayload, Encoding.UTF8, "application/vnd.docker.distribution.manifest.v2+json")
            };
            response.Headers.Add("Docker-Content-Digest", computedHash);
            return response;
        });

        var client = new HttpClient(mockHandler);
        var verifier = new RegistryManifestProvenanceVerifier(client, NullLogger<RegistryManifestProvenanceVerifier>.Instance);

        var result = await verifier.VerifyManifestDigestAsync(manifest);

        Assert.False(result.IsVerified);
        Assert.Equal(computedHash, result.ResolvedDigest);
        Assert.Contains("Digest mismatch", result.ErrorMessage);
    }

    [Fact]
    public async Task VerifyManifestDigest_HeaderPayloadDiscrepancy_FailsClosed()
    {
        var rawPayload = "{\"schemaVersion\":2}";
        var headerDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        var manifest = CreateManifest(headerDigest);

        var mockHandler = new MockHttpMessageHandler((req) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(rawPayload, Encoding.UTF8, "application/vnd.docker.distribution.manifest.v2+json")
            };
            response.Headers.Add("Docker-Content-Digest", headerDigest);
            return response;
        });

        var client = new HttpClient(mockHandler);
        var verifier = new RegistryManifestProvenanceVerifier(client, NullLogger<RegistryManifestProvenanceVerifier>.Instance);

        var result = await verifier.VerifyManifestDigestAsync(manifest);

        Assert.False(result.IsVerified);
        Assert.Contains("integrity breach", result.ErrorMessage);
    }

    private sealed class MockHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

        public MockHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            _responder = responder;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_responder(request));
        }
    }
}
