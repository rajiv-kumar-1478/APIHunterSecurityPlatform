using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acornima;
using Acornima.Ast;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.JavaScript;

/// <summary>
/// Authoritative AST data-flow analyzer tracking untrusted sources to dangerous DOM sinks
/// with bounded taint propagation, sanitizer recognition, and calibrated confidence.
/// </summary>
public sealed class JsDataFlowAnalyzer : IJsDataFlowAnalyzer
{
    public const int MaxTaintHops = 5;
    public const int MaxFlowsPerAsset = 50;
    public const int MaxNodesPerAsset = 15_000;
    public const int MaxSnippetLength = 500;

    private readonly ILogger<JsDataFlowAnalyzer> _logger;

    public JsDataFlowAnalyzer(ILogger<JsDataFlowAnalyzer> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public JsDataFlowAnalysisResult AnalyzeDataFlow(
        Guid scanJobId,
        IReadOnlyList<(JavaScriptAsset Asset, string Content)> assets)
    {
        if (assets == null || assets.Count == 0)
        {
            return new JsDataFlowAnalysisResult(
                scanJobId,
                Array.Empty<DataFlowTaintPath>(),
                0,
                0,
                0,
                Array.Empty<FindingCandidate>()
            );
        }

        var allFlows = new List<DataFlowTaintPath>();
        var candidates = new List<FindingCandidate>();
        var seenFingerprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int totalSources = 0;
        int totalSinks = 0;
        int exhaustionCount = 0;

        foreach (var (asset, content) in assets)
        {
            if (string.IsNullOrWhiteSpace(content)) continue;

            try
            {
                var parser = new Parser(new ParserOptions
                {
                    Tolerant = true
                });

                Program? program = null;
                try
                {
                    program = parser.ParseScript(content);
                }
                catch
                {
                    try
                    {
                        program = parser.ParseModule(content);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Data-flow AST parsing failed for asset '{Url}'.", asset.CanonicalUrl);
                    }
                }

                if (program == null) continue;

                var visitor = new TaintAstVisitor(asset.CanonicalUrl, content, MaxTaintHops, MaxNodesPerAsset, MaxFlowsPerAsset);
                visitor.Visit(program);

                totalSources += visitor.SourcesDiscovered;
                totalSinks += visitor.SinksDiscovered;
                if (visitor.NodeBudgetExhausted || visitor.FlowBudgetExhausted)
                {
                    exhaustionCount++;
                }

                foreach (var flow in visitor.DetectedFlows)
                {
                    if (seenFingerprints.Add(flow.FlowFingerprint))
                    {
                        allFlows.Add(flow);

                        // Generate Candidate
                        var rawEvidence = JsonSerializer.Serialize(new
                        {
                            flow.SourceKind,
                            flow.SourceExpression,
                            flow.SourceLine,
                            flow.TransformationHops,
                            flow.DetectedSanitizer,
                            flow.IsSanitizerVerified,
                            flow.SinkKind,
                            flow.SinkExpression,
                            flow.SinkLine,
                            flow.CodeSnippet,
                            flow.Confidence
                        });

                        var candidate = new FindingCandidate(
                            ToolKey: "jsminer",
                            ToolVersion: "1.2.0",
                            FindingType: FindingType.ProductionServiceExposed,
                            Title: "Potential DOM-Based Cross-Site Scripting (DOM-XSS)",
                            Description: $"Potential client-side DOM-XSS data flow from untrusted source '{flow.SourceExpression}' (Line {flow.SourceLine}) to dangerous sink '{flow.SinkExpression}' (Line {flow.SinkLine}) with {flow.Confidence} confidence.",
                            RawSeverity: flow.Confidence == FindingConfidence.Medium ? "medium" : "low",
                            TargetUrl: flow.AssetUrl,
                            CweId: "CWE-79",
                            EndpointPath: new Uri(flow.AssetUrl).AbsolutePath,
                            HttpMethod: "GET",
                            ParameterName: flow.SourceExpression,
                            RuleOrTemplateId: "dom-xss-potential",
                            RawEvidenceJson: rawEvidence,
                            ObservedAtUtc: DateTime.UtcNow
                        );

                        candidates.Add(candidate);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to analyze data flows for asset '{Url}'.", asset.CanonicalUrl);
            }
        }

        return new JsDataFlowAnalysisResult(
            scanJobId,
            allFlows.AsReadOnly(),
            totalSources,
            totalSinks,
            exhaustionCount,
            candidates.AsReadOnly()
        );
    }

    private sealed class TaintInfo
    {
        public TaintSourceKind SourceKind { get; init; }
        public string SourceExpression { get; init; } = string.Empty;
        public int SourceLine { get; init; }
        public int Hops { get; init; }
        public List<string> Transformations { get; } = new();
        public SanitizerKind Sanitizer { get; set; } = SanitizerKind.None;
    }

    private sealed class TaintAstVisitor
    {
        private readonly string _assetUrl;
        private readonly string _sourceCode;
        private readonly int _maxHops;
        private readonly int _maxNodes;
        private readonly int _maxFlows;

        private int _nodeCount;
        public bool NodeBudgetExhausted { get; private set; }
        public bool FlowBudgetExhausted { get; private set; }
        public int SourcesDiscovered { get; private set; }
        public int SinksDiscovered { get; private set; }

        private readonly Dictionary<string, TaintInfo> _taintScope = new(StringComparer.Ordinal);
        public List<DataFlowTaintPath> DetectedFlows { get; } = new();

        public TaintAstVisitor(string assetUrl, string sourceCode, int maxHops, int maxNodes, int maxFlows)
        {
            _assetUrl = assetUrl;
            _sourceCode = sourceCode;
            _maxHops = maxHops;
            _maxNodes = maxNodes;
            _maxFlows = maxFlows;
        }

        public void Visit(Node? node)
        {
            if (node == null || NodeBudgetExhausted || FlowBudgetExhausted) return;

            _nodeCount++;
            if (_nodeCount > _maxNodes)
            {
                NodeBudgetExhausted = true;
                return;
            }

            switch (node)
            {
                case VariableDeclarator varDecl:
                    HandleVariableDeclarator(varDecl);
                    break;

                case AssignmentExpression assignExpr:
                    HandleAssignmentExpression(assignExpr);
                    break;

                case CallExpression callExpr:
                    HandleCallExpression(callExpr);
                    break;
            }

            foreach (var child in node.ChildNodes)
            {
                Visit(child);
            }
        }

        private void HandleVariableDeclarator(VariableDeclarator decl)
        {
            if (decl.Id is Identifier id && decl.Init != null)
            {
                var taint = EvaluateTaint(decl.Init);
                if (taint != null)
                {
                    _taintScope[id.Name] = taint;
                }
            }
        }

        private void HandleAssignmentExpression(AssignmentExpression assign)
        {
            var rightTaint = EvaluateTaint(assign.Right);

            // 1. Check if left side is a variable identifier receiving taint
            if (assign.Left is Identifier id && rightTaint != null)
            {
                _taintScope[id.Name] = rightTaint;
            }

            // 2. Check if left side is a dangerous DOM Sink
            if (assign.Left is MemberExpression member)
            {
                var propName = GetMemberPropertyName(member);
                if (IsDangerousDomSinkProperty(propName, out var sinkKind))
                {
                    SinksDiscovered++;
                    if (rightTaint != null)
                    {
                        RecordFlow(rightTaint, sinkKind, $"{GetMemberExpressionString(member)} = ...", member.Location.Start.Line, assign);
                    }
                }
            }
        }

        private void HandleCallExpression(CallExpression call)
        {
            var calleeName = GetCalleeName(call.Callee);

            if (calleeName is "document.write" or "document.writeln" or "write" or "writeln")
            {
                SinksDiscovered++;
                if (call.Arguments.Count > 0)
                {
                    var argTaint = EvaluateTaint(call.Arguments[0]);
                    if (argTaint != null)
                    {
                        RecordFlow(argTaint, TaintSinkKind.DocumentWrite, $"{calleeName}(...)", call.Location.Start.Line, call);
                    }
                }
            }
            else if (calleeName is "eval" or "window.eval")
            {
                SinksDiscovered++;
                if (call.Arguments.Count > 0)
                {
                    var argTaint = EvaluateTaint(call.Arguments[0]);
                    if (argTaint != null)
                    {
                        RecordFlow(argTaint, TaintSinkKind.Eval, "eval(...)", call.Location.Start.Line, call);
                    }
                }
            }
            else if (calleeName is "setTimeout" or "setInterval" or "window.setTimeout" or "window.setInterval")
            {
                if (call.Arguments.Count > 0)
                {
                    var firstArg = call.Arguments[0];
                    if (firstArg is not FunctionExpression && firstArg is not ArrowFunctionExpression)
                    {
                        SinksDiscovered++;
                        var argTaint = EvaluateTaint(firstArg);
                        if (argTaint != null)
                        {
                            RecordFlow(argTaint, TaintSinkKind.TimerString, $"{calleeName}(string, ...)", call.Location.Start.Line, call);
                        }
                    }
                }
            }
        }

        private TaintInfo? EvaluateTaint(Expression expr)
        {
            if (expr == null) return null;

            // Direct Source
            var sourceKind = DetectTaintSource(expr, out var sourceExpr);
            if (sourceKind != null)
            {
                SourcesDiscovered++;
                return new TaintInfo
                {
                    SourceKind = sourceKind.Value,
                    SourceExpression = sourceExpr,
                    SourceLine = expr.Location.Start.Line,
                    Hops = 1
                };
            }

            // Variable Lookup
            if (expr is Identifier id && _taintScope.TryGetValue(id.Name, out var existingTaint))
            {
                if (existingTaint.Hops >= _maxHops) return null; // Bound exceeded

                var cloned = new TaintInfo
                {
                    SourceKind = existingTaint.SourceKind,
                    SourceExpression = existingTaint.SourceExpression,
                    SourceLine = existingTaint.SourceLine,
                    Hops = existingTaint.Hops + 1,
                    Sanitizer = existingTaint.Sanitizer
                };
                cloned.Transformations.AddRange(existingTaint.Transformations);
                return cloned;
            }

            // Call Expression (Transformation or Sanitizer)
            if (expr is CallExpression call)
            {
                var calleeName = GetCalleeName(call.Callee);

                if (call.Arguments.Count > 0)
                {
                    var innerTaint = EvaluateTaint(call.Arguments[0]);
                    if (innerTaint != null)
                    {
                        if (calleeName.Contains("DOMPurify", StringComparison.OrdinalIgnoreCase))
                        {
                            innerTaint.Sanitizer = SanitizerKind.DomPurify;
                        }
                        else if (calleeName.Equals("encodeURIComponent", StringComparison.OrdinalIgnoreCase))
                        {
                            innerTaint.Sanitizer = SanitizerKind.EncodeUriComponent;
                        }
                        else if (calleeName.Contains("escape", StringComparison.OrdinalIgnoreCase) ||
                                 calleeName.Contains("sanitize", StringComparison.OrdinalIgnoreCase))
                        {
                            innerTaint.Sanitizer = SanitizerKind.CustomOrUnverified;
                        }
                        else
                        {
                            innerTaint.Transformations.Add(calleeName);
                        }

                        return innerTaint;
                    }
                }
            }

            // Template Literal: `<div>${userInput}</div>`
            if (expr is TemplateLiteral template)
            {
                foreach (var element in template.Expressions)
                {
                    var elementTaint = EvaluateTaint(element);
                    if (elementTaint != null)
                    {
                        elementTaint.Transformations.Add("TemplateLiteralInterpolation");
                        return elementTaint;
                    }
                }
            }

            // Binary Expression: "<div>" + userInput + "</div>"
            if (expr is BinaryExpression binary)
            {
                var leftTaint = EvaluateTaint(binary.Left);
                if (leftTaint != null) return leftTaint;

                var rightTaint = EvaluateTaint(binary.Right);
                if (rightTaint != null) return rightTaint;
            }

            return null;
        }

        private static TaintSourceKind? DetectTaintSource(Expression expr, out string sourceExpr)
        {
            sourceExpr = string.Empty;

            if (expr is MemberExpression member)
            {
                var memberStr = GetMemberExpressionString(member);

                if (memberStr.Equals("location.hash", StringComparison.OrdinalIgnoreCase) ||
                    memberStr.Equals("window.location.hash", StringComparison.OrdinalIgnoreCase))
                {
                    sourceExpr = memberStr;
                    return TaintSourceKind.LocationHash;
                }

                if (memberStr.Equals("location.search", StringComparison.OrdinalIgnoreCase) ||
                    memberStr.Equals("window.location.search", StringComparison.OrdinalIgnoreCase))
                {
                    sourceExpr = memberStr;
                    return TaintSourceKind.LocationSearch;
                }

                if (memberStr.Equals("location.href", StringComparison.OrdinalIgnoreCase) ||
                    memberStr.Equals("window.location.href", StringComparison.OrdinalIgnoreCase) ||
                    memberStr.Equals("document.location.href", StringComparison.OrdinalIgnoreCase))
                {
                    sourceExpr = memberStr;
                    return TaintSourceKind.LocationHref;
                }

                if (memberStr.Equals("document.referrer", StringComparison.OrdinalIgnoreCase))
                {
                    sourceExpr = memberStr;
                    return TaintSourceKind.DocumentReferrer;
                }

                if (memberStr.Equals("window.name", StringComparison.OrdinalIgnoreCase) ||
                    memberStr.Equals("name", StringComparison.OrdinalIgnoreCase))
                {
                    sourceExpr = memberStr;
                    return TaintSourceKind.WindowName;
                }

                if (memberStr.EndsWith(".data", StringComparison.OrdinalIgnoreCase))
                {
                    sourceExpr = memberStr;
                    return TaintSourceKind.PostMessageData;
                }
            }

            return null;
        }

        private static bool IsDangerousDomSinkProperty(string propertyName, out TaintSinkKind sinkKind)
        {
            sinkKind = TaintSinkKind.InnerHtml;

            if (propertyName.Equals("innerHTML", StringComparison.OrdinalIgnoreCase))
            {
                sinkKind = TaintSinkKind.InnerHtml;
                return true;
            }

            if (propertyName.Equals("outerHTML", StringComparison.OrdinalIgnoreCase))
            {
                sinkKind = TaintSinkKind.OuterHtml;
                return true;
            }

            if (propertyName.Equals("href", StringComparison.OrdinalIgnoreCase) ||
                propertyName.Equals("src", StringComparison.OrdinalIgnoreCase))
            {
                sinkKind = TaintSinkKind.NavigationAssignment;
                return true;
            }

            return false;
        }

        private void RecordFlow(TaintInfo taint, TaintSinkKind sinkKind, string sinkExpr, int sinkLine, Node node)
        {
            if (DetectedFlows.Count >= _maxFlows)
            {
                FlowBudgetExhausted = true;
                return;
            }

            var confidence = taint.Sanitizer == SanitizerKind.None
                ? FindingConfidence.Medium
                : FindingConfidence.Low;

            var snippet = ExtractSnippet(node);
            var fingerprint = ComputeFlowFingerprint(_assetUrl, taint.SourceKind, sinkKind, taint.SourceLine, sinkLine);

            DetectedFlows.Add(new DataFlowTaintPath(
                FlowId: Guid.NewGuid(),
                AssetUrl: _assetUrl,
                SourceKind: taint.SourceKind,
                SourceExpression: taint.SourceExpression,
                SourceLine: taint.SourceLine,
                TransformationHops: taint.Transformations.AsReadOnly(),
                DetectedSanitizer: taint.Sanitizer,
                IsSanitizerVerified: false, // Unverified effectiveness
                SinkKind: sinkKind,
                SinkExpression: sinkExpr,
                SinkLine: sinkLine,
                CodeSnippet: snippet,
                Confidence: confidence,
                FlowFingerprint: fingerprint
            ));
        }

        private string ExtractSnippet(Node node)
        {
            try
            {
                var start = node.Location.Start.Line - 1;
                var lines = _sourceCode.Split('\n');
                if (start >= 0 && start < lines.Length)
                {
                    var raw = lines[start].Trim();
                    return raw.Length > MaxSnippetLength ? raw[..MaxSnippetLength] : raw;
                }
            }
            catch { }

            return string.Empty;
        }

        private static string GetCalleeName(Expression callee)
        {
            if (callee is Identifier id) return id.Name;
            if (callee is MemberExpression member) return GetMemberExpressionString(member);
            return string.Empty;
        }

        private static string GetMemberPropertyName(MemberExpression member)
        {
            if (member.Property is Identifier id) return id.Name;
            return string.Empty;
        }

        private static string GetMemberExpressionString(MemberExpression member)
        {
            var obj = member.Object switch
            {
                Identifier id => id.Name,
                MemberExpression subMember => GetMemberExpressionString(subMember),
                _ => string.Empty
            };

            var prop = member.Property switch
            {
                Identifier id => id.Name,
                _ => string.Empty
            };

            return string.IsNullOrEmpty(obj) ? prop : $"{obj}.{prop}";
        }

        private static string ComputeFlowFingerprint(string assetUrl, TaintSourceKind source, TaintSinkKind sink, int sourceLine, int sinkLine)
        {
            var raw = $"{assetUrl}:{source}:{sink}:{sourceLine}:{sinkLine}";
            var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }
    }
}
