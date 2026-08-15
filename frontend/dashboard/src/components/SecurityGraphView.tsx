"use client";

import { useEffect, useState } from "react";
import { GraphData, getSecurityGraph } from "@/lib/security-api";

interface Props {
  repositoryId?: string;
}

export function SecurityGraphView({ repositoryId }: Props) {
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function loadGraph() {
      setLoading(true);
      const data = await getSecurityGraph(repositoryId);
      setGraph(data);
      setLoading(false);
    }
    loadGraph();
  }, [repositoryId]);

  const nodeColor = (type: string) => {
    switch (type.toLowerCase()) {
      case "repository": return "border-blue-500 bg-blue-950/80 text-blue-300";
      case "credentialcandidate": return "border-red-500 bg-red-950/80 text-red-300";
      case "service": return "border-purple-500 bg-purple-950/80 text-purple-300";
      case "database": return "border-green-500 bg-green-950/80 text-green-300";
      case "environment": return "border-yellow-500 bg-yellow-950/80 text-yellow-300";
      default: return "border-cyan-500 bg-cyan-950/80 text-cyan-300";
    }
  };

  return (
    <div className="glass-card p-4 mb-6">
      <div className="flex items-center justify-between border-b pb-3 mb-4" style={{ borderColor: "var(--border-subtle)" }}>
        <h3 className="text-sm font-semibold flex items-center gap-2" style={{ fontFamily: "Outfit, sans-serif" }}>
          <span>🕸️</span> Security Intelligence Graph Visualizer
        </h3>
        <span className="text-xs text-muted font-mono">
          {graph ? `${graph.nodes.length} Nodes · ${graph.edges.length} Edges` : "Loading..."}
        </span>
      </div>

      {loading ? (
        <div className="py-12 text-center text-xs text-muted animate-pulse">
          Loading intelligence graph nodes and edges…
        </div>
      ) : !graph || graph.nodes.length === 0 ? (
        <div className="py-8 text-center text-xs text-muted">
          No security intelligence nodes linked to this scope.
        </div>
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 max-h-80 overflow-y-auto p-2 border rounded border-slate-800 bg-slate-950/60">
            {graph.nodes.map((node) => (
              <div
                key={node.id}
                className={`p-3 rounded border text-xs flex flex-col justify-between ${nodeColor(node.nodeType)}`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] uppercase font-bold tracking-wider">{node.nodeType}</span>
                    <span className="text-[10px] text-muted">{node.discoverySource}</span>
                  </div>
                  <p className="font-semibold text-foreground truncate">{node.label}</p>
                  <p className="text-[10px] text-muted truncate font-mono">{node.name}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Relationship Edge Table */}
          {graph.edges.length > 0 && (
            <div className="border rounded border-slate-800 overflow-hidden text-[11px]">
              <div className="bg-slate-900/80 px-3 py-1.5 font-semibold text-muted uppercase tracking-wider text-[10px]">
                Graph Relationships ({graph.edges.length})
              </div>
              <div className="divide-y divide-slate-800/60 max-h-36 overflow-y-auto">
                {graph.edges.map((edge) => (
                  <div key={edge.id} className="p-2 flex items-center justify-between text-muted">
                    <span className="font-mono text-cyan-400">{edge.edgeType}</span>
                    <span>Weight: <strong className="text-foreground">{edge.weight}</strong></span>
                    <span className="text-[10px]">{edge.discoverySource}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
