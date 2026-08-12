using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public class AwsStsCredentialValidator : BaseCredentialValidator
{
    public override string ProviderName => "AWSIAM";

    public AwsStsCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<AwsStsCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }

    protected override async Task<ValidationResultDto> ExecuteValidationAsync(CredentialCandidate candidate, string decryptedSecret, Stopwatch stopwatch, CancellationToken ct)
    {
        // Extract AccessKeyId, SecretAccessKey, and optional SessionToken from candidate context
        var (accessKeyId, secretAccessKey, sessionToken) = ParseAwsCredentialTuple(decryptedSecret);

        if (string.IsNullOrWhiteSpace(accessKeyId) || string.IsNullOrWhiteSpace(secretAccessKey))
        {
            stopwatch.Stop();
            return new ValidationResultDto(ValidationStatus.Invalid, ValidationConfidence.Strong, "Missing AWS AccessKeyId or SecretAccessKey", "{}", stopwatch.ElapsedMilliseconds);
        }

        using var client = CreateSsrfClient();
        using var request = BuildSigV4StsRequest(accessKeyId, secretAccessKey, sessionToken);

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, ct);
        }
        catch (HttpRequestException ex)
        {
            stopwatch.Stop();
            return new ValidationResultDto(ValidationStatus.Unavailable, ValidationConfidence.Indeterminate, $"Network error: {ex.Message}", "{}", stopwatch.ElapsedMilliseconds);
        }

        stopwatch.Stop();
        int statusCode = (int)response.StatusCode;
        string xmlContent = await response.Content.ReadAsStringAsync(ct);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var (arn, userId, account) = ParseGetCallerIdentityXml(xmlContent);
            bool isRootAccount = arn.Contains(":root", StringComparison.OrdinalIgnoreCase);

            var evidence = System.Text.Json.JsonSerializer.Serialize(new
            {
                arn,
                userId,
                account,
                isRootAccount,
                latencyMs = stopwatch.ElapsedMilliseconds
            });

            return new ValidationResultDto(ValidationStatus.Valid, ValidationConfidence.Confirmed, "HTTP 200 OK — AWS STS GetCallerIdentity Verified", evidence, stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (xmlContent.Contains("InvalidClientTokenId", StringComparison.OrdinalIgnoreCase) ||
            xmlContent.Contains("SignatureDoesNotMatch", StringComparison.OrdinalIgnoreCase) ||
            xmlContent.Contains("UnrecognizedClientException", StringComparison.OrdinalIgnoreCase))
        {
            return new ValidationResultDto(ValidationStatus.Invalid, ValidationConfidence.Confirmed, "AWS STS Authentication Failed — Invalid credentials", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (xmlContent.Contains("AccessDenied", StringComparison.OrdinalIgnoreCase))
        {
            return new ValidationResultDto(ValidationStatus.ValidInsufficientScope, ValidationConfidence.Strong, "HTTP 403 AccessDenied — AWS credentials valid but STS access restricted", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.TooManyRequests || xmlContent.Contains("Throttling", StringComparison.OrdinalIgnoreCase))
        {
            return new ValidationResultDto(ValidationStatus.RateLimited, ValidationConfidence.Strong, "AWS STS Rate Limited / Throttled", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        return new ValidationResultDto(ValidationStatus.ValidationError, ValidationConfidence.Indeterminate, $"HTTP {statusCode} — AWS STS Error", "{}", stopwatch.ElapsedMilliseconds, statusCode);
    }

    private static (string accessKeyId, string secretAccessKey, string? sessionToken) ParseAwsCredentialTuple(string decryptedSecret)
    {
        // Secret may be formatted as "AKIA...:secretKey" or "AKIA...:secretKey:sessionToken" or raw secret if candidate masked value holds AccessKeyId
        string[] parts = decryptedSecret.Split(':', ';', '|', ' ');
        if (parts.Length >= 2 && parts[0].StartsWith("AKIA", StringComparison.OrdinalIgnoreCase) || parts[0].StartsWith("ASIA", StringComparison.OrdinalIgnoreCase))
        {
            string session = parts.Length >= 3 ? parts[2] : null!;
            return (parts[0], parts[1], session);
        }

        return (string.Empty, string.Empty, null);
    }

    private static HttpRequestMessage BuildSigV4StsRequest(string accessKeyId, string secretAccessKey, string? sessionToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "https://sts.amazonaws.com/");
        string requestBody = "Action=GetCallerIdentity&Version=2011-06-15";
        request.Content = new StringContent(requestBody, Encoding.UTF8, "application/x-www-form-urlencoded");

        DateTime now = DateTime.UtcNow;
        string amzDate = now.ToString("yyyyMMddTHHmmssZ");
        string dateStamp = now.ToString("yyyyMMdd");

        request.Headers.Add("X-Amz-Date", amzDate);
        if (!string.IsNullOrWhiteSpace(sessionToken))
        {
            request.Headers.Add("X-Amz-Security-Token", sessionToken);
        }

        // Minimal AWS SigV4 Header Calculation for sts.amazonaws.com
        string region = "us-east-1";
        string service = "sts";
        string credentialScope = $"{dateStamp}/{region}/{service}/aws4_request";

        byte[] payloadHash = SHA256.HashData(Encoding.UTF8.GetBytes(requestBody));
        string payloadHashHex = Convert.ToHexStringLower(payloadHash);

        string canonicalHeaders = $"content-type:application/x-www-form-urlencoded\nhost:sts.amazonaws.com\nx-amz-date:{amzDate}\n";
        string signedHeaders = "content-type;host;x-amz-date";
        if (!string.IsNullOrWhiteSpace(sessionToken))
        {
            canonicalHeaders = $"content-type:application/x-www-form-urlencoded\nhost:sts.amazonaws.com\nx-amz-date:{amzDate}\nx-amz-security-token:{sessionToken}\n";
            signedHeaders = "content-type;host;x-amz-date;x-amz-security-token";
        }

        string canonicalRequest = $"POST\n/\n\n{canonicalHeaders}\n{signedHeaders}\n{payloadHashHex}";
        string canonicalRequestHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest)));

        string stringToSign = $"AWS4-HMAC-SHA256\n{amzDate}\n{credentialScope}\n{canonicalRequestHash}";

        byte[] kDate = HmacSha256(Encoding.UTF8.GetBytes("AWS4" + secretAccessKey), dateStamp);
        byte[] kRegion = HmacSha256(kDate, region);
        byte[] kService = HmacSha256(kRegion, service);
        byte[] kSigning = HmacSha256(kService, "aws4_request");

        byte[] signatureBytes = HmacSha256(kSigning, stringToSign);
        string signature = Convert.ToHexStringLower(signatureBytes);

        string authHeader = $"AWS4-HMAC-SHA256 Credential={accessKeyId}/{credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}";
        request.Headers.TryAddWithoutValidation("Authorization", authHeader);

        return request;
    }

    private static byte[] HmacSha256(byte[] key, string data)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
    }

    private static (string arn, string userId, string account) ParseGetCallerIdentityXml(string xml)
    {
        try
        {
            var xdoc = XDocument.Parse(xml);
            var ns = xdoc.Root?.GetDefaultNamespace() ?? XNamespace.None;
            var result = xdoc.Root?.Element(ns + "GetCallerIdentityResult");

            string arn = result?.Element(ns + "Arn")?.Value ?? "Unknown";
            string userId = result?.Element(ns + "UserId")?.Value ?? "Unknown";
            string account = result?.Element(ns + "Account")?.Value ?? "Unknown";

            return (arn, userId, account);
        }
        catch
        {
            return ("Unknown", "Unknown", "Unknown");
        }
    }
}
