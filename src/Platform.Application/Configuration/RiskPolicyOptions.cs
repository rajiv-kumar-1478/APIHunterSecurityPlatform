using Platform.Domain.Enums;

namespace Platform.Application.Configuration;

public class RiskPolicyOptions
{
    public const string SectionName = "RiskPolicy";

    public string AlgorithmVersion { get; set; } = "v1.0";

    // Base Floors by FindingType
    public int BaseFloorValidatedCredentialExposed { get; set; } = 40;
    public int BaseFloorProductionServiceExposed { get; set; } = 30;
    public int BaseFloorDatabaseExposure { get; set; } = 30;
    public int BaseFloorUnvalidatedCredentialExposed { get; set; } = 20;
    public int BaseFloorHistoricalExposureDetected { get; set; } = 15;
    public int BaseFloorOverprivilegedCredential { get; set; } = 15;

    // Factor Weights
    public int WeightCredentialValid { get; set; } = 30;
    public int WeightCredentialValidInsufficientScope { get; set; } = 20;
    public int WeightProductionEnvironment { get; set; } = 20;
    public int WeightProductionDatabase { get; set; } = 20;
    public int WeightInternetFacingService { get; set; } = 15;
    public int WeightHistoricalCommit { get; set; } = 10;
    public int WeightAiHighConfidence { get; set; } = 10;
    public int WeightMultiSourceCorroboration { get; set; } = 5;
    public int WeightCredentialRevokedOrInvalid { get; set; } = -30;

    // Severity Thresholds
    public int CriticalThreshold { get; set; } = 80;
    public int HighThreshold { get; set; } = 60;
    public int MediumThreshold { get; set; } = 35;
}
