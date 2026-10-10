import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  ChevronRight,
  Database,
  FileCheck2,
  Gauge,
  IndianRupee,
  ListTree,
  Loader2,
  PiggyBank,
  ShieldCheck,
  SlidersHorizontal,
  TrendingDown,
  TrendingUp,
  Swords,
  Wallet,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import "./App.css";

const API_BASE =
  (import.meta.env.VITE_API_BASE_URL || "http://localhost:8000") + "/api";

async function apiCall(path, options = {}) {
  const response = await fetch(API_BASE + path, {
    headers: {
      "Content-Type": "application/json",
    },
    ...options,
  });

  let data = null;

  try {
    data = await response.json();
  } catch {
    throw new Error("Invalid response from " + path);
  }

  if (!response.ok) {
    throw new Error(
      data?.message || `${path} failed (${response.status})`
    );
  }

  return data;
}

function formatINR(value) {
  if (
    value === null ||
    value === undefined ||
    Number.isNaN(Number(value))
  ) {
    return "—";
  }

  const amount = Number(value);

  if (amount >= 10000000) {
    return `₹${(amount / 10000000).toFixed(amount >= 100000000 ? 0 : 1)} Cr`;
  }

  if (amount >= 100000) {
    return `₹${(amount / 100000).toFixed(amount >= 1000000 ? 0 : 1)} L`;
  }

  if (amount >= 1000) {
    return `₹${(amount / 1000).toFixed(1)}K`;
  }

  return `₹${Math.round(amount)}`;
}

function formatROSI(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return "—";
  }

  return `${(Number(value) / 100).toFixed(1)}×`;
}

function assetMeta(asset) {
  if (!asset) {
    return { number: "—", name: "Unknown asset", department: "—", label: "Unknown asset" };
  }

  const number = asset.id || "—";
  const rawName = asset.name || "Unnamed asset";
  const department = asset.business_unit || "Unassigned";

  // Convert internal host-style identifiers into a human-readable asset name.
  // Example: db-01.finance.aegisq.local -> DB 01
  const firstSegment = rawName.split(".")[0] || rawName;
  const tokens = firstSegment.replace(/[-_]+/g, " ").trim();
  const aliases = [
    [/^db\s*(\d+)$/i, "Database $1"],
    [/^laptop\s*(\d+)$/i, "Employee Laptop $1"],
    [/^mail\s*(\d+)$/i, "Email Server $1"],
    [/^payment\s*gateway\s*(\d+)$/i, "Payment Gateway $1"],
    [/^firewall(?:\s*hq)?$/i, "Firewall"],
    [/^router\s*(\d+)$/i, "Router $1"],
    [/^vpn\s*gateway\s*(\d+)$/i, "VPN Gateway $1"],
    [/^web\s*(?:application|server)\s*(\d+)$/i, "Web Application $1"],
    [/^iot\s*sensor\s*(\d+)$/i, "IoT Sensor $1"],
  ];
  let name = null;
  for (const [pattern, replacement] of aliases) {
    if (pattern.test(tokens)) {
      name = tokens.replace(pattern, replacement);
      break;
    }
  }
  if (!name) {
    name = tokens.replace(/\b\w/g, (char) => char.toUpperCase());
  }

  return {
    number,
    name,
    department,
    rawName,
    label: `${number} · ${name} · ${department}`,
  };
}

// Presentational-only helper: classifies a CVSS score into a severity tier
// so vulnerability rows can be scanned by color instead of raw numbers.
// Thresholds follow the common CVSS v3 severity bands.
function cvssSeverity(score) {
  const value = Number(score);

  if (Number.isNaN(value)) {
    return { label: "—", className: "badge" };
  }

  if (value >= 9) {
    return { label: "Critical", className: "badge badge-critical" };
  }

  if (value >= 7) {
    return { label: "High", className: "badge badge-high" };
  }

  if (value >= 4) {
    return { label: "Medium", className: "badge badge-medium" };
  }

  return { label: "Low", className: "badge badge-low" };
}

function severityDotClass(score) {
  const value = Number(score);

  if (Number.isNaN(value)) return "severity-dot";
  if (value >= 9) return "severity-dot sev-critical";
  if (value >= 7) return "severity-dot sev-high";
  if (value >= 4) return "severity-dot sev-medium";
  return "severity-dot sev-low";
}

// Presentational-only helper: maps a compliance framework name to a badge
// color so the mapping table is scannable at a glance. Falls back to a
// neutral badge for any framework name not explicitly recognized.
function frameworkBadgeClass(framework) {
  const key = (framework || "").toUpperCase();

  if (key.includes("ISO")) return "badge badge-framework-iso";
  if (key.includes("NIST")) return "badge badge-framework-nist";
  if (key.includes("CIS")) return "badge badge-framework-cis";
  if (key.includes("RBI")) return "badge badge-framework-rbi";

  return "badge";
}

function useResource(path) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(Boolean(path));
  const [error, setError] = useState(null);

  const reload = useCallback(() => {
    if (!path) {
      setData(null);
      setLoading(false);
      setError(null);
      return;
    }

    setLoading(true);
    setError(null);

    apiCall(path)
      .then((result) => {
        setData(result);
      })
      .catch((err) => {
        setError(err.message);
        setData(null);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [path]);

  useEffect(() => {
    reload();
  }, [reload]);

  return {
    data,
    loading,
    error,
    reload,
  };
}

function Panel({ title, eyebrow, children }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          {eyebrow && <div className="panel-eyebrow">{eyebrow}</div>}
          <h2 className="panel-title">{title}</h2>
        </div>
      </div>

      <div className="panel-body">{children}</div>
    </section>
  );
}

function Status({ loading, error, retry }) {
  if (loading) {
    return (
      <div className="status-row">
        <Loader2 size={15} className="spin" />
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div className="status-row status-error">
        <AlertTriangle size={15} />
        <span>{error}</span>
        <button className="link-btn" onClick={retry}>
          retry
        </button>
      </div>
    );
  }

  return null;
}

const TABS = [
  {
    id: "overview",
    label: "Overview",
    icon: Gauge,
  },
  {
    id: "assets",
    label: "Assets & vulnerabilities",
    icon: ListTree,
  },
  {
    id: "simulator",
    label: "Scenario simulator",
    icon: SlidersHorizontal,
  },
  {
    id: "optimizer",
    label: "Investment optimizer",
    icon: IndianRupee,
  },
  {
    id: "compliance",
    label: "Compliance mapping",
    icon: FileCheck2,
  },
  {
    id: "attacks",
    label: "Attack intelligence",
    icon: Swords,
  },
];

export default function App() {
  const [tab, setTab] = useState("overview");

  const health = useResource("/health");
  const summary = useResource("/risk/summary");
  const assets = useResource("/assets");
  const controls = useResource("/controls");
  const compliance = useResource("/compliance/mapping");
  const attacks = useResource("/attacks/summary");
  const mlStatus = useResource("/ml/status");
  const portfolioOutlook = useResource("/ml/risk-outlook");

  const [selectedAssetId, setSelectedAssetId] = useState(null);

  const assetDetail = useResource(
    selectedAssetId
      ? `/risk/assets/${selectedAssetId}`
      : null
  );

  const mlPrediction = useResource(
    selectedAssetId
      ? `/ml/predict/${selectedAssetId}`
      : null
  );

  const attackLossPrediction = useResource(
    selectedAssetId
      ? `/ml/attack-loss/asset/${selectedAssetId}`
      : null
  );

  useEffect(() => {
    if (
      !selectedAssetId &&
      Array.isArray(assets.data) &&
      assets.data.length > 0
    ) {
      setSelectedAssetId(assets.data[0].id);
    }
  }, [assets.data, selectedAssetId]);

  const [pickedControls, setPickedControls] = useState([]);
  const [simLoading, setSimLoading] = useState(false);
  const [simError, setSimError] = useState(null);
  const [simResult, setSimResult] = useState(null);

  const [budget, setBudget] = useState(2500000);
  const [optLoading, setOptLoading] = useState(false);
  const [optError, setOptError] = useState(null);
  const [optResult, setOptResult] = useState(null);

  function toggleControl(id) {
    setPickedControls((current) => {
      if (current.includes(id)) {
        return current.filter((item) => item !== id);
      }

      return [...current, id];
    });

    setSimResult(null);
  }

  async function runSimulation() {
    if (pickedControls.length === 0) {
      return;
    }

    setSimLoading(true);
    setSimError(null);

    try {
      const result = await apiCall("/scenario/simulate", {
        method: "POST",
        body: JSON.stringify({
          control_ids: pickedControls,
        }),
      });

      setSimResult(result);
    } catch (error) {
      setSimError(error.message);
    } finally {
      setSimLoading(false);
    }
  }

  async function runOptimize() {
    setOptLoading(true);
    setOptError(null);

    try {
      const result = await apiCall("/optimize", {
        method: "POST",
        body: JSON.stringify({
          budget_inr: Number(budget),
        }),
      });

      setOptResult(result);
    } catch (error) {
      setOptError(error.message);
    } finally {
      setOptLoading(false);
    }
  }

  const riskScore = summary.data?.enterprise_risk_score ?? null;

  const exposure =
    summary.data?.total_financial_exposure_inr ?? null;

  // When a scenario has been simulated, surface the hypothetical result
  // in the headline KPIs so the user can immediately see the modeled impact.
  // The underlying current-state API data remains unchanged.
  const displayedRiskScore =
    simResult?.new_enterprise_risk_score ?? riskScore;

  const displayedExposure =
    simResult?.new_total_financial_exposure_inr ?? exposure;

  const isSimulatedView = Boolean(simResult);

  const contributors =
    summary.data?.top_risk_contributors || [];

  const contributorsWithMeta = contributors.map((item) => {
    const asset = (assets.data || []).find(
      (candidate) => candidate.id === item.asset_id
    );
    return {
      ...item,
      asset_label: assetMeta(asset).label,
    };
  });

  const selectedAsset =
    (assets.data || []).find(
      (asset) => asset.id === selectedAssetId
    ) || null;

  const simExposureImproved = (simResult?.delta_inr || 0) > 0;

  return (
    <div className="aq-root">
      <header className="aq-header">
        <div className="aq-brand">
          <div className="aq-brand-icon">
            <ShieldCheck size={20} />
          </div>

          <div className="aq-brand-text">
            <div className="aq-brand-row">
              <span className="aq-brand-mark">AegisQ</span>
              <span className="aq-brand-badge">SIH26105</span>
            </div>

            <span className="aq-brand-sub">
              Cyber risk, quantified in rupees
            </span>
          </div>
        </div>

        <div className="health-pill">
          <span
            className="health-dot"
            style={{
              background: health.error
                ? "#9e3040"
                : health.data
                  ? "#70c99e"
                  : "#b07a58",
            }}
          />

          {health.loading && "checking backend..."}

          {health.error && "backend unreachable"}

          {health.data && !health.error && (
            <span className="mono">
              {health.data.status || "online"} · assets{" "}
              {health.data.row_counts?.assets ?? "—"} · vulns{" "}
              {health.data.row_counts?.vulnerabilities ?? "—"} · controls{" "}
              {health.data.row_counts?.controls ?? "—"}
            </span>
          )}
        </div>
      </header>

      <div className="kpi-strip">
        <div className="kpi-cell kpi-cell--primary kpi-cell--risk">
          <div className="kpi-icon-badge">
            <Gauge size={16} />
          </div>

          <div className="kpi-label">
            {isSimulatedView
              ? "simulated enterprise risk score"
              : "enterprise risk score"}
          </div>

          {summary.loading ? (
            <div className="kpi-value small">
              Loading...
            </div>
          ) : summary.error ? (
            <div className="kpi-value small delta-bad">
              unavailable
            </div>
          ) : (
            <>
              <div className="kpi-value">
                {displayedRiskScore !== null
                  ? Number(displayedRiskScore).toFixed(1)
                  : "—"}

                <span
                  style={{
                    fontSize: 15,
                    fontWeight: 500,
                    color: "var(--text-faint)",
                  }}
                >
                  {" "}
                  / 100
                </span>
              </div>

              <div className="risk-scale">
                <div className="risk-scale-track">
                  <div
                    style={{
                      width: "34%",
                      background: "var(--success)",
                    }}
                  />

                  <div
                    style={{
                      width: "33%",
                      background: "var(--warning)",
                    }}
                  />

                  <div
                    style={{
                      width: "33%",
                      background: "var(--accent)",
                    }}
                  />

                  <div
                    className="risk-scale-marker"
                    style={{
                      left:
                        Math.max(
                          2,
                          Math.min(
                            98,
                            Number(displayedRiskScore) || 0
                          )
                        ) + "%",
                    }}
                  />
                </div>
              </div>
            </>
          )}
        </div>

        <div className="kpi-cell kpi-cell--primary kpi-cell--exposure">
          <div className="kpi-icon-badge">
            <Wallet size={16} />
          </div>

          <div className="kpi-label">
            {isSimulatedView
              ? "simulated financial exposure"
              : "total financial exposure"}
          </div>

          {summary.loading ? (
            <div className="kpi-value small">
              Loading...
            </div>
          ) : summary.error ? (
            <div className="kpi-value small delta-bad">
              unavailable
            </div>
          ) : (
            <>
              <div className="kpi-value">
                {formatINR(displayedExposure)}
              </div>
              <div className="kpi-subtext">
                expected annual loss, portfolio-wide
              </div>
              {isSimulatedView && (
                <div className="kpi-simulated-note">
                  what-if scenario · current baseline preserved
                </div>
              )}
            </>
          )}
        </div>

        <div className="kpi-cell kpi-cell--contributor">
          <div className="kpi-icon-badge">
            <AlertTriangle size={15} />
          </div>

          <div className="kpi-label">
            top contributor
          </div>

          {summary.loading || summary.error ? (
            <div className="kpi-value small">
              —
            </div>
          ) : (
            <>
              <div className="asset-summary-block">
                <div className="asset-summary-number">
                  {assetMeta(
                    (assets.data || []).find(
                      (asset) => asset.id === contributors[0]?.asset_id
                    )
                  ).number}
                </div>
                <div className="asset-summary-name">
                  {assetMeta(
                    (assets.data || []).find(
                      (asset) => asset.id === contributors[0]?.asset_id
                    )
                  ).name}
                </div>
                <div className="asset-summary-department">
                  {assetMeta(
                    (assets.data || []).find(
                      (asset) => asset.id === contributors[0]?.asset_id
                    )
                  ).department}
                </div>
              </div>

              <div className="kpi-subtext">
                {formatINR(
                  contributors[0]?.expected_annual_loss_inr
                )}{" "}
                expected annual loss
              </div>
            </>
          )}
        </div>
      </div>

      <nav className="aq-tabs">
        {TABS.map((item) => {
          const Icon = item.icon;

          return (
            <button
              key={item.id}
              className={
                "aq-tab " +
                (tab === item.id ? "active" : "")
              }
              onClick={() => setTab(item.id)}
            >
              <Icon size={14} />
              {item.label}
            </button>
          );
        })}
      </nav>

      <main className="aq-content">
        {tab === "overview" && (
          <div className="grid-2">
            <Panel
              eyebrow="90-day trend"
              title="Expected annual loss"
            >
              <Status
                loading={summary.loading}
                error={summary.error}
                retry={summary.reload}
              />

              {!summary.loading &&
                !summary.error && (
                  <ResponsiveContainer
                    width="100%"
                    height={280}
                  >
                    <LineChart
                      data={
                        summary.data?.risk_trend || []
                      }
                    >
                      <defs>
                        <linearGradient
                          id="aqLineFade"
                          x1="0"
                          y1="0"
                          x2="0"
                          y2="1"
                        >
                          <stop
                            offset="0%"
                            stopColor="var(--accent-strong)"
                            stopOpacity={0.28}
                          />
                          <stop
                            offset="100%"
                            stopColor="var(--accent-strong)"
                            stopOpacity={0}
                          />
                        </linearGradient>
                      </defs>

                      <CartesianGrid
                        stroke="rgba(175,223,228,0.10)"
                        vertical={false}
                      />

                      <XAxis
                        dataKey="date"
                        tick={{
                          fill: "var(--text-faint)",
                          fontSize: 11,
                        }}
                        axisLine={{
                          stroke: "rgba(175,223,228,0.12)",
                        }}
                        tickLine={false}
                      />

                      <YAxis
                        tickFormatter={(value) => formatINR(value)}
                        tick={{
                          fill: "var(--text-faint)",
                          fontSize: 11,
                        }}
                        axisLine={false}
                        tickLine={false}
                      />

                      <Tooltip
                        formatter={(value) =>
                          formatINR(value)
                        }
                        contentStyle={{
                          background: "rgba(15, 30, 44, 0.97)",
                          border: "1px solid rgba(175,223,228,0.18)",
                          borderRadius: 8,
                          fontSize: 12.5,
                        }}
                        labelStyle={{ color: "var(--text-muted)" }}
                      />

                      <Area
                        type="monotone"
                        dataKey="expected_annual_loss_inr"
                        stroke="none"
                        fill="url(#aqLineFade)"
                      />

                      <Line
                        type="monotone"
                        dataKey="expected_annual_loss_inr"
                        stroke="var(--accent-strong)"
                        strokeWidth={2.5}
                        dot={false}
                        activeDot={{ r: 4 }}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                )}
            </Panel>

            <Panel
              eyebrow="ranked by exposure"
              title="Top risk contributors"
            >
              <Status
                loading={summary.loading}
                error={summary.error}
                retry={summary.reload}
              />

              {!summary.loading &&
                !summary.error && (
                  <ResponsiveContainer
                    width="100%"
                    height={280}
                  >
                    <BarChart
                      data={contributorsWithMeta}
                      layout="vertical"
                      margin={{ left: 10 }}
                    >
                      <CartesianGrid
                        stroke="rgba(175,223,228,0.10)"
                        horizontal={false}
                      />

                      <XAxis
                        type="number"
                        tickFormatter={(value) => formatINR(value)}
                        tick={{
                          fill: "var(--text-faint)",
                          fontSize: 11,
                        }}
                        axisLine={false}
                        tickLine={false}
                      />

                      <YAxis
                        type="category"
                        dataKey="asset_label"
                        width={210}
                        tick={{
                          fill: "var(--text-muted)",
                          fontSize: 12,
                        }}
                        axisLine={false}
                        tickLine={false}
                      />

                      <Tooltip
                        formatter={(value) =>
                          formatINR(value)
                        }
                        cursor={{ fill: "rgba(194,59,74,0.08)" }}
                        contentStyle={{
                          background: "rgba(15, 30, 44, 0.97)",
                          border: "1px solid rgba(175,223,228,0.18)",
                          borderRadius: 8,
                          fontSize: 12.5,
                        }}
                        labelStyle={{ color: "var(--text-muted)" }}
                      />

                      <Bar
                        dataKey="expected_annual_loss_inr"
                        radius={[0, 4, 4, 0]}
                      >
                        {contributorsWithMeta.map(
                          (item, index) => (
                            <Cell
                              key={
                                item.asset_id ||
                                index
                              }
                              fill={
                                index === 0
                                  ? "var(--accent)"
                                  : "var(--warning)"
                              }
                              cursor="pointer"
                              onClick={() => {
                                if (
                                  item.asset_id
                                ) {
                                  setSelectedAssetId(
                                    item.asset_id
                                  );

                                  setTab("assets");
                                }
                              }}
                            />
                          )
                        )}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                )}
            </Panel>
          </div>
        )}

        {tab === "overview" && portfolioOutlook.data && (
          <div className="portfolio-forecast-card">
            <Panel eyebrow="machine-learning forecast" title="Portfolio risk outlook">
              <div className="portfolio-forecast-values">
                <div>
                  <div className="kpi-label">current</div>
                  <div className="forecast-big">{Number(portfolioOutlook.data.current_risk_score).toFixed(1)}</div>
                </div>
                <div className="forecast-arrow">→</div>
                <div>
                  <div className="kpi-label">next-day model</div>
                  <div className="forecast-big">{Number(portfolioOutlook.data.predicted_next_day_risk_score).toFixed(1)}</div>
                </div>
                <div className="forecast-copy">
                  <div>Exposure</div>
                  <strong>{formatINR(portfolioOutlook.data.current_exposure_inr)}</strong>
                  <span>→ {formatINR(portfolioOutlook.data.predicted_next_day_exposure_inr)}</span>
                </div>
              </div>
              <div className="forecast-footnote">Risk forecast is a planning signal; current FAIR-style exposure remains authoritative.</div>
            </Panel>
          </div>
        )}

        {tab === "overview" && (
          <div className="ml-forecast-grid">
            <Panel eyebrow="machine-learning forecast" title="Risk outlook">
              <Status loading={mlPrediction.loading} error={mlPrediction.error} retry={mlPrediction.reload} />
              {!mlPrediction.loading && !mlPrediction.error && mlPrediction.data && (
                <div className="forecast-hero">
                  <div className="panel-eyebrow">
                    selected asset · {assetMeta(selectedAsset).label}
                  </div>
                  <div style={{ marginTop: 10, display: "flex", alignItems: "baseline", flexWrap: "wrap" }}>
                    <span className="forecast-big">{Number(mlPrediction.data.current_risk_score).toFixed(1)}</span>
                    <span className="forecast-arrow">→</span>
                    <span className="forecast-big" style={{ color: Number(mlPrediction.data.predicted_next_day_risk_score) > Number(mlPrediction.data.current_risk_score) ? "var(--critical)" : "var(--success)" }}>
                      {Number(mlPrediction.data.predicted_next_day_risk_score).toFixed(1)}
                    </span>
                  </div>
                  <div className="forecast-delta">
                    predicted next-period risk score · {Number(mlPrediction.data.predicted_next_day_risk_score - mlPrediction.data.current_risk_score).toFixed(1)} point change
                  </div>
                  <div className="forecast-meta">
                    <span>current exposure <strong>{formatINR(mlPrediction.data.current_expected_annual_loss_inr)}</strong></span>
                    <span>model R² <strong>{Number(mlPrediction.data.model_metrics?.r2 ?? 0).toFixed(4)}</strong></span>
                    <span>trained through <strong>{mlPrediction.data.trained_until || "—"}</strong></span>
                  </div>
                </div>
              )}
            </Panel>

            <Panel eyebrow="data readiness" title="Intelligence layer">
              <div className="data-chip-row">
                <span className="data-chip"><BrainCircuit size={12} /> ML forecast {mlStatus.data?.trained ? "ready" : "pending"}</span>
                <span className="data-chip"><Database size={12} /> {health.data?.row_counts?.vulnerabilities ?? "—"} vulnerabilities</span>
                <span className="data-chip"><Activity size={12} /> {health.data?.row_counts?.assets ?? "—"} assets</span>
                <span className="data-chip"><Swords size={12} /> {attacks.data?.incident_count ?? 0} attack incidents</span>
              </div>
              <div className="detail-kpis" style={{ marginTop: 20 }}>
                <div>
                  <div className="kpi-label">attack-loss ML signal</div>
                  <div className="kpi-value small">
                    {attackLossPrediction.data?.predicted_loss_inr != null
                      ? formatINR(attackLossPrediction.data.predicted_loss_inr)
                      : "No linked incidents"}
                  </div>
                  <div className="kpi-subtext">historical incident calibration for {assetMeta(selectedAsset).name}</div>
                </div>
                <div>
                  <div className="kpi-label">attack model</div>
                  <div className="kpi-value small">
                    {attackLossPrediction.data?.model_metrics ? "trained" : "pending"}
                  </div>
                  <div className="kpi-subtext">supplementary signal, not annual-loss ground truth</div>
                </div>
              </div>
              <div className="detail-kpis" style={{ marginTop: 20 }}>
                <div>
                  <div className="kpi-label">historical attack loss</div>
                  <div className="kpi-value small">{formatINR(attacks.data?.total_loss_inr || 0)}</div>
                </div>
                <div>
                  <div className="kpi-label">model status</div>
                  <div className="kpi-value small">{mlStatus.data?.trained ? "trained" : "not trained"}</div>
                </div>
              </div>
            </Panel>
          </div>
        )}

        {tab === "assets" && (
          <div className="grid-2">
            <Panel
              eyebrow={
                (assets.data?.length || 0) +
                " assets under coverage"
              }
              title="Asset register"
            >
              <Status
                loading={assets.loading}
                error={assets.error}
                retry={assets.reload}
              />

              {!assets.loading &&
                !assets.error && (
                  <table className="led">
                    <thead>
                      <tr>
                        <th>asset number</th>
                        <th>asset name</th>
                        <th>category</th>
                        <th>criticality</th>
                        <th>department</th>
                      </tr>
                    </thead>

                    <tbody>
                      {(assets.data || []).map(
                        (asset) => (
                          <tr
                            key={asset.id}
                            className={
                              "clickable " +
                              (asset.id ===
                              selectedAssetId
                                ? "selected"
                                : "")
                            }
                            onClick={() =>
                              setSelectedAssetId(
                                asset.id
                              )
                            }
                          >
                            <td className="mono">{asset.id}</td>

                            <td>
                              <span className="asset-table-name">{assetMeta(asset).name}</span>
                            </td>

                            <td className="mono">
                              {asset.category}
                            </td>

                            <td>
                              {asset.criticality ??
                                "—"}
                              /5
                            </td>

                            <td className="mono">
                              {asset.business_unit}
                            </td>
                          </tr>
                        )
                      )}
                    </tbody>
                  </table>
                )}
            </Panel>

            <Panel
              eyebrow={
                selectedAsset
                  ? `${selectedAsset.id} · ${selectedAsset.business_unit || "Unassigned"}`
                  : "asset drill-down"
              }
              title={
                selectedAsset
                  ? `${assetMeta(selectedAsset).number} · ${assetMeta(selectedAsset).name}`
                  : "Select an asset"
              }
            >
              <Status
                loading={assetDetail.loading}
                error={assetDetail.error}
                retry={assetDetail.reload}
              />

              {!assetDetail.loading &&
                !assetDetail.error &&
                assetDetail.data && (
                  <>
                    <div className="detail-kpis">
                      <div>
                        <div className="kpi-label">
                          risk score
                        </div>

                        <div className="kpi-value small">
                          {assetDetail.data
                            .risk_score !==
                          undefined
                            ? Number(
                                assetDetail.data
                                  .risk_score
                              ).toFixed(1)
                            : "—"}
                        </div>
                      </div>

                      <div>
                        <div className="kpi-label">
                          expected annual loss
                        </div>

                        <div className="kpi-value small">
                          {formatINR(
                            assetDetail.data
                              .expected_annual_loss_inr
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="panel-eyebrow">
                      vulnerabilities
                    </div>

                    <table className="led">
                      <thead>
                        <tr>
                          <th>CVE</th>
                          <th>severity</th>
                          <th>EPSS</th>
                        </tr>
                      </thead>

                      <tbody>
                        {(
                          assetDetail.data
                            .vulnerabilities || []
                        ).map(
                          (vulnerability) => {
                            const severity = cvssSeverity(
                              vulnerability.cvss_score
                            );

                            const epssPct =
                              vulnerability.epss_score
                                ? Number(
                                    vulnerability.epss_score
                                  ) * 100
                                : 0;

                            return (
                              <tr
                                key={
                                  vulnerability.id ||
                                  vulnerability.cve_id
                                }
                              >
                                <td className="mono">
                                  {
                                    vulnerability.cve_id
                                  }
                                </td>

                                <td>
                                  <div className="severity-cell">
                                    <span
                                      className={severityDotClass(
                                        vulnerability.cvss_score
                                      )}
                                    />
                                    <span
                                      className={
                                        severity.className
                                      }
                                    >
                                      {severity.label}
                                      {" · "}
                                      {vulnerability.cvss_score ??
                                        "—"}
                                    </span>
                                  </div>
                                </td>

                                <td>
                                  {vulnerability.epss_score ? (
                                    <div className="epss-cell">
                                      <div className="epss-bar-track">
                                        <div
                                          className="epss-bar-fill"
                                          style={{
                                            width:
                                              Math.min(
                                                100,
                                                epssPct
                                              ) + "%",
                                          }}
                                        />
                                      </div>
                                      <span className="epss-value">
                                        {epssPct.toFixed(
                                          1
                                        )}
                                        %
                                      </span>
                                    </div>
                                  ) : (
                                    "—"
                                  )}
                                </td>
                              </tr>
                            );
                          }
                        )}
                      </tbody>
                    </table>
                  </>
                )}
            </Panel>
          </div>
        )}

        {tab === "simulator" && (
          <div className="grid-2">
            <Panel
              eyebrow="choose controls"
              title="Scenario builder"
            >
              <Status
                loading={controls.loading}
                error={controls.error}
                retry={controls.reload}
              />

              {!controls.loading &&
                !controls.error && (
                  <>
                    <div className="picked-count">
                      {pickedControls.length} of{" "}
                      {controls.data?.length || 0}{" "}
                      controls selected
                    </div>

                    {(controls.data || []).map(
                      (control) => {
                        const isPicked =
                          pickedControls.includes(
                            control.id
                          );

                        return (
                          <label
                            className={
                              "control-row" +
                              (isPicked
                                ? " picked"
                                : "")
                            }
                            key={control.id}
                          >
                            <input
                              type="checkbox"
                              checked={isPicked}
                              onChange={() =>
                                toggleControl(
                                  control.id
                                )
                              }
                            />

                            <div>
                              <div className="control-row-name">
                                {control.name}
                              </div>

                              <div className="control-meta">
                                <span className="control-pill">
                                  {formatINR(
                                    control.cost_inr
                                  )}
                                </span>

                                <span className="control-pill reduction">
                                  −
                                  {
                                    control.risk_reduction_pct
                                  }
                                  % risk
                                </span>
                              </div>
                            </div>
                          </label>
                        );
                      }
                    )}

                    <button
                      className="btn-primary"
                      disabled={
                        simLoading ||
                        pickedControls.length === 0
                      }
                      onClick={runSimulation}
                    >
                      {simLoading ? (
                        <Loader2
                          size={14}
                          className="spin"
                        />
                      ) : (
                        <ChevronRight size={14} />
                      )}

                      Run simulation
                    </button>
                  </>
                )}
            </Panel>

            <Panel
              eyebrow="modeled outcome"
              title="Simulation result"
            >
              {simError && (
                <div className="status-row status-error">
                  <AlertTriangle size={15} />
                  {simError}
                </div>
              )}

              {!simResult && !simError && (
                <div className="empty-state">
                  <SlidersHorizontal
                    size={22}
                    className="empty-state-icon"
                  />
                  Select one or more security controls
                  and run the simulation.
                </div>
              )}

              {simResult && (
                <>
                  <div className="comparison-grid">
                    <div className="comparison-card">
                      <div className="comparison-label">
                        current
                      </div>
                      <div className="comparison-value">
                        {riskScore !== null
                          ? Number(riskScore).toFixed(1)
                          : "—"}
                      </div>
                      <div className="comparison-sub">
                        enterprise risk score
                      </div>
                      <div className="comparison-exposure">
                        {formatINR(exposure)}
                      </div>
                      <div className="comparison-sub">
                        expected annual loss
                      </div>
                    </div>

                    <div className="comparison-arrow">
                      →
                    </div>

                    <div className="comparison-card">
                      <div className="comparison-label">
                        simulated
                      </div>
                      <div className="comparison-value success-value">
                        {simResult.new_enterprise_risk_score !==
                        undefined
                          ? Number(
                              simResult.new_enterprise_risk_score
                            ).toFixed(1)
                          : "—"}
                      </div>
                      <div className="comparison-sub">
                        enterprise risk score
                      </div>
                      <div className="comparison-exposure success-value">
                        {formatINR(
                          simResult.new_total_financial_exposure_inr
                        )}
                      </div>
                      <div className="comparison-sub">
                        expected annual loss
                      </div>
                    </div>
                  </div>

                  <div
                    className={
                      "delta-banner " +
                      (simExposureImproved ? "good" : "bad")
                    }
                  >
                    {simExposureImproved ? (
                      <TrendingDown size={18} />
                    ) : (
                      <TrendingUp size={18} />
                    )}

                    <span>
                      {formatINR(
                        Math.abs(simResult.delta_inr || 0)
                      )}{" "}
                      {simExposureImproved
                        ? "reduction"
                        : "increase"}{" "}
                      in exposure
                    </span>
                  </div>

                  <div className="simulation-meta">
                    <span>
                      investment: {" "}
                      <strong>
                        {formatINR(simResult.total_cost_inr)}
                      </strong>
                    </span>
                    <span>
                      ROSI: {" "}
                      <strong>
                        {formatROSI(simResult.rosi_pct)}
                      </strong>
                    </span>
                  </div>

                  <button
                    className="link-btn simulation-reset"
                    onClick={() => setSimResult(null)}
                  >
                    Clear simulation and restore current score
                  </button>
                </>
              )}
            </Panel>
          </div>
        )}

        {tab === "optimizer" && (
          <div className="grid-2">
            <Panel
              eyebrow="constrained by budget"
              title="Investment optimizer"
            >
              <label className="field-label">
                annual security budget
              </label>

              <input
                type="number"
                className="field-input"
                value={budget}
                onChange={(event) =>
                  setBudget(event.target.value)
                }
              />

              <button
                className="btn-primary"
                disabled={optLoading}
                onClick={runOptimize}
              >
                {optLoading ? (
                  <Loader2
                    size={14}
                    className="spin"
                  />
                ) : (
                  <ChevronRight size={14} />
                )}

                Optimize allocation
              </button>

              {optError && (
                <div className="status-row status-error">
                  <AlertTriangle size={15} />
                  {optError}
                </div>
              )}

              {optResult && (
                <div className="optimizer-result">
                  <div className="flow-strip">
                    <div className="flow-step">
                      <div className="flow-step-icon">
                        <Wallet size={14} />
                      </div>
                      <div className="flow-step-label">
                        budget
                      </div>
                      <div className="flow-step-value">
                        {formatINR(budget)}
                      </div>
                    </div>

                    <div className="flow-arrow">
                      <ChevronRight size={16} />
                    </div>

                    <div className="flow-step">
                      <div className="flow-step-icon">
                        <ShieldCheck size={14} />
                      </div>
                      <div className="flow-step-label">
                        recommended spend
                      </div>
                      <div className="flow-step-value">
                        {formatINR(
                          optResult.total_cost_inr
                        )}
                      </div>
                    </div>

                    <div className="flow-arrow">
                      <ChevronRight size={16} />
                    </div>

                    <div className="flow-step is-success">
                      <div className="flow-step-icon">
                        <TrendingDown size={14} />
                      </div>
                      <div className="flow-step-label">
                        risk reduction
                      </div>
                      <div className="flow-step-value">
                        {formatINR(
                          optResult
                            .total_risk_reduction_inr
                        )}
                      </div>
                    </div>

                    <div className="flow-arrow">
                      <ChevronRight size={16} />
                    </div>

                    <div className="flow-step is-success">
                      <div className="flow-step-icon">
                        <PiggyBank size={14} />
                      </div>
                      <div className="flow-step-label">
                        ROSI
                      </div>
                      <div className="flow-step-value rosi-highlight">
                        {optResult.rosi_pct !== undefined ? formatROSI(optResult.rosi_pct) : "—"}
                      </div>
                      <div className="flow-step-note">net value per ₹1 invested</div>
                    </div>
                  </div>

                  <div className="panel-eyebrow">
                    selected controls
                  </div>

                  <table className="led">
                    <thead>
                      <tr>
                        <th>control</th>
                        <th>cost</th>
                      </tr>
                    </thead>

                    <tbody>
                      {(
                        optResult.selected_controls ||
                        []
                      ).map((control) => (
                        <tr
                          key={
                            control.control_id
                          }
                        >
                          <td>{control.name}</td>

                          <td className="mono">
                            {formatINR(
                              control.cost_inr
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>

            <Panel
              eyebrow="risk reduction vs spend"
              title="Investment curve"
            >
              {optResult?.investment_curve ? (
                <ResponsiveContainer
                  width="100%"
                  height={280}
                >
                  <AreaChart
                    data={
                      optResult.investment_curve
                    }
                  >
                    <defs>
                      <linearGradient
                        id="aqAreaFade"
                        x1="0"
                        y1="0"
                        x2="0"
                        y2="1"
                      >
                        <stop
                          offset="0%"
                          stopColor="var(--success)"
                          stopOpacity={0.32}
                        />
                        <stop
                          offset="100%"
                          stopColor="var(--success)"
                          stopOpacity={0.02}
                        />
                      </linearGradient>
                    </defs>

                    <CartesianGrid
                      stroke="rgba(175,223,228,0.10)"
                      vertical={false}
                    />

                    <XAxis
                      dataKey="spend_inr"
                      tickFormatter={(value) => formatINR(value)}
                      tick={{
                        fill: "var(--text-faint)",
                        fontSize: 11,
                      }}
                      axisLine={{
                        stroke: "rgba(175,223,228,0.12)",
                      }}
                      tickLine={false}
                    />

                    <YAxis
                      tickFormatter={(value) => formatINR(value)}
                      tick={{
                        fill: "var(--text-faint)",
                        fontSize: 11,
                      }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <Tooltip
                      formatter={(value) =>
                        formatINR(value)
                      }
                      contentStyle={{
                        background: "rgba(15, 30, 44, 0.97)",
                        border: "1px solid rgba(175,223,228,0.18)",
                        borderRadius: 8,
                        fontSize: 12.5,
                      }}
                      labelStyle={{ color: "var(--text-muted)" }}
                    />

                    <Area
                      type="monotone"
                      dataKey="risk_reduction_inr"
                      stroke="var(--success)"
                      strokeWidth={2.5}
                      fill="url(#aqAreaFade)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty-state">
                  <IndianRupee
                    size={22}
                    className="empty-state-icon"
                  />
                  Run the optimizer to see the
                  projected risk reduction curve.
                </div>
              )}
            </Panel>
          </div>
        )}

        {tab === "attacks" && (
          <div className="grid-1">
            <Panel eyebrow="historical cyber incidents" title="Attack intelligence dataset">
              <Status loading={attacks.loading} error={attacks.error} retry={attacks.reload} />
              {!attacks.loading && !attacks.error && (
                <>
                  <div className="detail-kpis" style={{ marginBottom: 18 }}>
                    <div><div className="kpi-label">incidents</div><div className="kpi-value small">{attacks.data?.incident_count ?? 0}</div></div>
                    <div><div className="kpi-label">reported loss</div><div className="kpi-value small">{formatINR(attacks.data?.total_loss_inr || 0)}</div></div>
                  </div>
                  <div className="grid-2">
                    <div>
                      <div className="panel-eyebrow">by attack type</div>
                      <table className="led"><thead><tr><th>type</th><th>incidents</th><th>loss</th></tr></thead><tbody>
                        {(attacks.data?.by_attack_type || []).map((row) => <tr key={row.attack_type}><td>{row.attack_type || "Unknown"}</td><td>{row.incidents}</td><td>{formatINR(row.loss_inr)}</td></tr>)}
                      </tbody></table>
                    </div>
                    <div>
                      <div className="panel-eyebrow">by threat actor</div>
                      <table className="led"><thead><tr><th>actor</th><th>incidents</th><th>loss</th></tr></thead><tbody>
                        {(attacks.data?.by_threat_actor || []).map((row) => <tr key={row.threat_actor}><td>{row.threat_actor || "Unknown"}</td><td>{row.incidents}</td><td>{formatINR(row.loss_inr)}</td></tr>)}
                      </tbody></table>
                    </div>
                  </div>
                  {(attacks.data?.incident_count ?? 0) === 0 && (
                    <div className="empty-state" style={{ marginTop: 18 }}>
                      <Swords size={22} className="empty-state-icon" />
                      No incident rows yet. Populate the attack dataset to train the loss model.
                    </div>
                  )}
                </>
              )}
            </Panel>
          </div>
        )}

        {tab === "compliance" && (
          <Panel
            eyebrow={
              (compliance.data?.length || 0) +
              " mapped clauses"
            }
            title="Framework coverage"
          >
            <Status
              loading={compliance.loading}
              error={compliance.error}
              retry={compliance.reload}
            />

            {!compliance.loading &&
              !compliance.error && (
                <table className="led">
                  <thead>
                    <tr>
                      <th>framework</th>
                      <th>clause</th>
                      <th>related controls</th>
                    </tr>
                  </thead>

                  <tbody>
                    {(compliance.data || []).map(
                      (row, index) => (
                        <tr key={index}>
                          <td>
                            <span
                              className={frameworkBadgeClass(
                                row.framework
                              )}
                            >
                              {row.framework}
                            </span>
                          </td>

                          <td className="mono">
                            {row.clause}
                          </td>

                          <td>
                            {row.related_control_ids?.join(
                              ", "
                            ) || "—"}
                          </td>
                        </tr>
                      )
                    )}
                  </tbody>
                </table>
              )}
          </Panel>
        )}
      </main>
    </div>
  );
}
