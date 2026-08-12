using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public class SecurityIntelligenceGraphBuilder
{
    private readonly IPlatformDbContext _dbContext;
    private readonly ILogger<SecurityIntelligenceGraphBuilder> _logger;

    public SecurityIntelligenceGraphBuilder(IPlatformDbContext dbContext, ILogger<SecurityIntelligenceGraphBuilder> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task BuildGraphForRepositoryAsync(Guid repositoryId, CancellationToken ct = default)
    {
        var repo = await _dbContext.Repositories
            .FirstOrDefaultAsync(r => r.Id == repositoryId, ct);

        if (repo == null)
        {
            _logger.LogError("Repository '{RepositoryId}' not found for graph build.", repositoryId);
            return;
        }

        _logger.LogInformation("Starting graph build for repository '{RepoName}' ({RepositoryId})...", repo.FullName, repositoryId);

        // 1. Ensure Repository Node exists
        var repoNode = await GetOrCreateNodeAsync(
            IntelligenceNodeType.Repository,
            $"repo:{repo.Id}",
            repo.FullName,
            repo.Id,
            JsonSerializer.Serialize(new { repo.Provider, repo.Url }),
            ct);

        // 2. Ingest APIHunter Seed Evidence (ApiHunterSync)
        await IngestApiHunterSeedsAsync(repo, repoNode, ct);

        // 3. Ingest Phase 3 Deterministic Detection Evidence (DeterministicDetector)
        await IngestDeterministicEvidenceAsync(repo, repoNode, ct);

        // 4. Ingest Phase 4 AI Investigation Evidence (AiInvestigator)
        await IngestAiInvestigationEvidenceAsync(repo, repoNode, ct);

        // 5. Ingest Phase 5 Credential Validation Evidence (CredentialValidation)
        await IngestCredentialValidationResultsAsync(repo, repoNode, ct);

        _logger.LogInformation("Completed graph build for repository '{RepoName}'.", repo.FullName);
    }

    private async Task IngestCredentialValidationResultsAsync(Repository repo, SecurityIntelligenceNode repoNode, CancellationToken ct)
    {
        var candidates = await _dbContext.CredentialCandidates
            .Include(c => c.Occurrences)
            .Where(c => c.Occurrences.Any(o => o.RepositoryId == repo.Id))
            .ToListAsync(ct);

        foreach (var cand in candidates)
        {
            var latestResult = await _dbContext.CredentialValidationResults
                .Where(r => r.CandidateId == cand.Id)
                .OrderByDescending(r => r.ValidatedAtUtc)
                .FirstOrDefaultAsync(ct);

            if (latestResult == null) continue;

            bool isCurrentlyValidated = latestResult.Status == ValidationStatus.Valid || latestResult.Status == ValidationStatus.ValidInsufficientScope;
            string statusTag = isCurrentlyValidated ? $"[{latestResult.Status}]" : $"[{latestResult.Status}]";

            // Retrieve or update candidate graph node
            var candNode = await GetOrCreateNodeAsync(
                IntelligenceNodeType.CredentialCandidate,
                $"candidate:{cand.Id}",
                $"{cand.CredentialType} ({cand.MaskedValue}) {statusTag}",
                cand.Id,
                JsonSerializer.Serialize(new
                {
                    cand.CredentialType,
                    cand.FingerprintKeyVersion,
                    latestValidationStatus = latestResult.Status.ToString(),
                    latestValidatedAtUtc = latestResult.ValidatedAtUtc,
                    latestValidationConfidence = latestResult.Confidence.ToString(),
                    isCurrentlyValidated,
                    responseClassification = latestResult.ResponseClassification
                }),
                ct);

            // Upsert validation enrichment edge with CredentialValidation discovery source
            await UpsertEdgeAsync(
                candNode.Id,
                repoNode.Id,
                IntelligenceEdgeType.AppearsIn,
                DiscoveryType.CredentialValidation,
                latestResult.Confidence == ValidationConfidence.Confirmed ? FindingConfidence.High : FindingConfidence.Medium,
                $"Validation Result #{latestResult.Id} (Status: {latestResult.Status}, ValidatedAt: {latestResult.ValidatedAtUtc:u})",
                ct);
        }
    }


    private async Task IngestApiHunterSeedsAsync(Repository repo, SecurityIntelligenceNode repoNode, CancellationToken ct)
    {
        var repoRefs = await _dbContext.ApiHunterRepoReferences
            .Include(r => r.ApiHunterRecord)
            .Where(r => r.RepoName == repo.FullName || repo.FullName.EndsWith(r.RepoName))
            .ToListAsync(ct);

        foreach (var r in repoRefs)
        {
            if (r.ApiHunterRecord == null) continue;

            var candNode = await GetOrCreateNodeAsync(
                IntelligenceNodeType.CredentialCandidate,
                $"candidate:apihunter:{r.ApiHunterRecord.Id}",
                $"{r.ApiHunterRecord.SearchProvider} ({r.ApiHunterRecord.MaskedKey})",
                r.ApiHunterRecord.Id,
                JsonSerializer.Serialize(new { r.ApiHunterRecord.Status, r.FilePath, r.LineNumber }),
                ct);

            await UpsertEdgeAsync(
                candNode.Id,
                repoNode.Id,
                IntelligenceEdgeType.DiscoveredIn,
                DiscoveryType.ApiHunterSync,
                FindingConfidence.High,
                $"APIHunter Reference #{r.Id} ({r.FilePath}:L{r.LineNumber})",
                ct);
        }
    }

    private async Task IngestDeterministicEvidenceAsync(Repository repo, SecurityIntelligenceNode repoNode, CancellationToken ct)
    {
        var candidates = await _dbContext.CredentialCandidates
            .Include(c => c.Occurrences)
            .Where(c => c.Occurrences.Any(o => o.RepositoryId == repo.Id))
            .ToListAsync(ct);

        foreach (var cand in candidates)
        {
            var candNode = await GetOrCreateNodeAsync(
                IntelligenceNodeType.CredentialCandidate,
                $"candidate:{cand.Id}",
                $"{cand.CredentialType} ({cand.MaskedValue})",
                cand.Id,
                JsonSerializer.Serialize(new { cand.CredentialType, cand.FingerprintKeyVersion }),
                ct);


            await UpsertEdgeAsync(
                candNode.Id,
                repoNode.Id,
                IntelligenceEdgeType.AppearsIn,
                DiscoveryType.DeterministicDetector,
                FindingConfidence.High,
                $"Deterministic Candidate #{cand.Id}",
                ct);
        }
    }

    private async Task IngestAiInvestigationEvidenceAsync(Repository repo, SecurityIntelligenceNode repoNode, CancellationToken ct)
    {
        var evidences = await _dbContext.AiInvestigationEvidences
            .Where(e => e.Snapshot.RepositoryId == repo.Id)
            .ToListAsync(ct);

        foreach (var ev in evidences)
        {
            try
            {
                using var doc = JsonDocument.Parse(ev.EvidenceJson);
                var root = doc.RootElement;

                // Extract Service Node if present
                if (root.TryGetProperty("service", out var serviceProp) && serviceProp.ValueKind == JsonValueKind.String)
                {
                    string rawService = serviceProp.GetString()!;
                    string normService = NormalizeServiceName(rawService);

                    var serviceNode = await GetOrCreateNodeAsync(
                        IntelligenceNodeType.Service,
                        $"service:{repo.Id}:{normService}",
                        normService,
                        repo.Id,
                        JsonSerializer.Serialize(new { serviceName = normService }),
                        ct);

                    await UpsertEdgeAsync(
                        serviceNode.Id,
                        repoNode.Id,
                        IntelligenceEdgeType.BelongsTo,
                        ev.Source,
                        ev.Confidence,
                        $"AI Evidence #{ev.Id} ({ev.FilePath}:L{ev.StartLine}-{ev.EndLine})",
                        ct);
                }

                // Extract Domain Node if present
                if (root.TryGetProperty("domain", out var domainProp) && domainProp.ValueKind == JsonValueKind.String)
                {
                    string normDomain = NormalizeDomain(domainProp.GetString()!);
                    if (!string.IsNullOrEmpty(normDomain))
                    {
                        var domainNode = await GetOrCreateNodeAsync(
                            IntelligenceNodeType.Domain,
                            $"domain:{normDomain}",
                            normDomain,
                            null,
                            JsonSerializer.Serialize(new { domain = normDomain }),
                            ct);

                        await UpsertEdgeAsync(
                            repoNode.Id,
                            domainNode.Id,
                            IntelligenceEdgeType.AssociatedWith,
                            ev.Source,
                            ev.Confidence,
                            $"AI Evidence #{ev.Id} ({ev.FilePath})",
                            ct);
                    }
                }

                // Extract Database Node if present
                if (root.TryGetProperty("databaseHost", out var dbProp) && dbProp.ValueKind == JsonValueKind.String)
                {
                    string normDb = NormalizeHost(dbProp.GetString()!);
                    if (!string.IsNullOrEmpty(normDb))
                    {
                        var dbNode = await GetOrCreateNodeAsync(
                            IntelligenceNodeType.Database,
                            $"db:{normDb}",
                            normDb,
                            null,
                            JsonSerializer.Serialize(new { host = normDb }),
                            ct);

                        await UpsertEdgeAsync(
                            repoNode.Id,
                            dbNode.Id,
                            IntelligenceEdgeType.RelatedTo,
                            ev.Source,
                            ev.Confidence,
                            $"AI Evidence #{ev.Id} ({ev.FilePath})",
                            ct);
                    }
                }

                // Extract Environment Node if present
                if (root.TryGetProperty("environment", out var envProp) && envProp.ValueKind == JsonValueKind.String)
                {
                    string normEnv = NormalizeEnvironment(envProp.GetString()!);
                    var envNode = await GetOrCreateNodeAsync(
                        IntelligenceNodeType.Environment,
                        $"env:{repo.Id}:{normEnv}",
                        normEnv,
                        repo.Id,
                        JsonSerializer.Serialize(new { environment = normEnv }),
                        ct);

                    await UpsertEdgeAsync(
                        repoNode.Id,
                        envNode.Id,
                        IntelligenceEdgeType.AssociatedWith,
                        ev.Source,
                        ev.Confidence,
                        $"AI Evidence #{ev.Id}",
                        ct);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse structured Json metadata for Evidence #{EvidenceId}. Skipping edge extraction.", ev.Id);
            }
        }
    }

    public virtual async Task<SecurityIntelligenceNode> GetOrCreateNodeAsync(
        IntelligenceNodeType nodeType,
        string name,
        string label,
        Guid? relatedEntityId,
        string metadataJson,
        CancellationToken ct)
    {
        var existing = await _dbContext.SecurityIntelligenceNodes
            .FirstOrDefaultAsync(n => n.NodeType == nodeType && n.Name == name, ct);

        if (existing != null)
        {
            existing.LastObservedAtUtc = DateTime.UtcNow;
            if (!string.IsNullOrWhiteSpace(label)) existing.Label = label;
            if (!string.IsNullOrWhiteSpace(metadataJson)) existing.MetadataJson = metadataJson;
            await _dbContext.SaveChangesAsync(ct);
            return existing;
        }


        var node = new SecurityIntelligenceNode
        {
            NodeType = nodeType,
            Name = name,
            Label = label,
            RelatedEntityId = relatedEntityId,
            MetadataJson = metadataJson,
            FirstObservedAtUtc = DateTime.UtcNow,
            LastObservedAtUtc = DateTime.UtcNow,
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityIntelligenceNodes.Add(node);
        await _dbContext.SaveChangesAsync(ct);
        return node;
    }

    public async Task<SecurityIntelligenceEdge> UpsertEdgeAsync(
        Guid sourceNodeId,
        Guid targetNodeId,
        IntelligenceEdgeType edgeType,
        DiscoveryType discoverySource,
        FindingConfidence confidence,
        string evidenceRef,
        CancellationToken ct)
    {
        var existing = await _dbContext.SecurityIntelligenceEdges
            .FirstOrDefaultAsync(e => e.SourceNodeId == sourceNodeId && e.TargetNodeId == targetNodeId && e.EdgeType == edgeType, ct);

        if (existing != null)
        {
            existing.LastObservedAtUtc = DateTime.UtcNow;
            if ((int)confidence > (int)existing.Confidence)
            {
                existing.Confidence = confidence;
            }
            if (!existing.EvidenceReference.Contains(evidenceRef))
            {
                existing.EvidenceReference = $"{existing.EvidenceReference}; {evidenceRef}";
            }
            await _dbContext.SaveChangesAsync(ct);
            return existing;
        }

        var edge = new SecurityIntelligenceEdge
        {
            SourceNodeId = sourceNodeId,
            TargetNodeId = targetNodeId,
            EdgeType = edgeType,
            DiscoverySource = discoverySource,
            Confidence = confidence,
            EvidenceReference = evidenceRef,
            FirstObservedAtUtc = DateTime.UtcNow,
            LastObservedAtUtc = DateTime.UtcNow,
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityIntelligenceEdges.Add(edge);
        await _dbContext.SaveChangesAsync(ct);
        return edge;
    }

    public static string NormalizeDomain(string rawUrlOrDomain)
    {
        if (string.IsNullOrWhiteSpace(rawUrlOrDomain)) return string.Empty;
        var trimmed = rawUrlOrDomain.Trim().ToLowerInvariant();
        if (trimmed.StartsWith("https://")) trimmed = trimmed["https://".Length..];
        if (trimmed.StartsWith("http://")) trimmed = trimmed["http://".Length..];
        var slashIdx = trimmed.IndexOf('/');
        if (slashIdx >= 0) trimmed = trimmed[..slashIdx];
        var colonIdx = trimmed.IndexOf(':');
        if (colonIdx >= 0) trimmed = trimmed[..colonIdx];
        return trimmed;
    }

    public static string NormalizeHost(string rawHost)
    {
        if (string.IsNullOrWhiteSpace(rawHost)) return string.Empty;
        return rawHost.Trim().ToLowerInvariant().TrimEnd('/');
    }

    public static string NormalizeServiceName(string rawServiceName)
    {
        if (string.IsNullOrWhiteSpace(rawServiceName)) return "default-service";
        return rawServiceName.Trim().ToLowerInvariant().Replace(' ', '-').Replace('_', '-');
    }

    public static string NormalizeEnvironment(string rawEnv)
    {
        if (string.IsNullOrWhiteSpace(rawEnv)) return "production";
        var lower = rawEnv.Trim().ToLowerInvariant();
        if (lower.Contains("prod") || lower.Contains("live")) return "production";
        if (lower.Contains("stag")) return "staging";
        if (lower.Contains("dev")) return "development";
        if (lower.Contains("test")) return "testing";
        return lower;
    }
}
