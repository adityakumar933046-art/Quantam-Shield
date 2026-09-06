import React, { useEffect, useState } from 'react';
import { api } from '../../services/api';
import {
  Activity,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Shield,
  FileText,
  Percent,
  TrendingUp,
  Info,
  RefreshCw,
  AlertCircle
} from 'lucide-react';

interface AttackTypeStat {
  total?: number;
  detected?: number;
  missed?: number;
  detection_rate?: number;
  average_risk_score?: number;
  average_detection_time_ms?: number;
  avg_time_ms?: number;
  average_time_ms?: number;
}

interface PerformanceData {
  total_analyses?: number;
  successful_verifications?: number;
  failed_verifications?: number;
  threats_detected?: number;
  total_simulations?: number;
  detected_simulations?: number;
  missed_simulations?: number;
  detection_rate?: number;
  true_positives?: number;
  true_negatives?: number;
  false_positives?: number;
  false_negatives?: number;
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1_score?: number;
  average_analysis_time_ms?: number;
  average_detection_time_ms?: number;
  average_risk_score?: number;
  attack_type_breakdown?: Record<string, AttackTypeStat>;
  disclaimer?: string;
}

// Null-safe numeric formatting helpers
export const safeToFixed = (val: any, digits: number = 2, fallback: string = 'N/A'): string => {
  if (val === null || val === undefined || val === '') return fallback;
  const num = Number(val);
  if (isNaN(num) || !isFinite(num)) return fallback;
  return num.toFixed(digits);
};

export const safeToPercent = (val: any, digits: number = 2, fallback: string = 'N/A'): string => {
  if (val === null || val === undefined || val === '') return fallback;
  const num = Number(val);
  if (isNaN(num) || !isFinite(num)) return fallback;
  return `${num.toFixed(digits)}%`;
};

export const safeRatioToPercent = (val: any, digits: number = 2, fallback: string = 'N/A'): string => {
  if (val === null || val === undefined || val === '') return fallback;
  const num = Number(val);
  if (isNaN(num) || !isFinite(num)) return fallback;
  return `${(num * 100).toFixed(digits)}%`;
};

export const safeProgressWidth = (val: any): string => {
  if (val === null || val === undefined || val === '') return '0%';
  const num = Number(val);
  if (isNaN(num) || !isFinite(num)) return '0%';
  const clamped = Math.max(0, Math.min(100, num * 100));
  return `${clamped.toFixed(2)}%`;
};

export const PerformanceEvaluationPage: React.FC = () => {
  const [data, setData] = useState<PerformanceData | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchPerformance = async () => {
    setIsRefreshing(true);
    setErrorMessage(null);
    try {
      const res = await api.get('/dashboard/simulation-performance');
      setData(res.data || {});
    } catch (err: any) {
      console.error('Failed to load performance metrics:', err);
      setErrorMessage(
        err?.response?.data?.detail ||
        err?.message ||
        'Unable to retrieve performance metrics. Displaying cached or baseline metrics.'
      );
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchPerformance();
  }, []);

  if (isLoading) {
    return (
      <div className="p-16 flex flex-col items-center justify-center space-y-4">
        <RefreshCw size={32} className="text-cyan animate-spin" />
        <p className="text-sm font-semibold text-cyber-secondary">
          Computing empirical defensive performance metrics from database...
        </p>
      </div>
    );
  }

  // Safe KPI resolutions using Number(val ?? 0).toFixed(2)
  const detectionRateDisplay = typeof data?.detection_rate === 'number'
    ? `${Number(data.detection_rate ?? 0).toFixed(2)}%`
    : safeToPercent(data?.detection_rate, 2);
  const f1ScoreDisplay = typeof data?.f1_score === 'number'
    ? Number(data.f1_score ?? 0).toFixed(4)
    : safeToFixed(data?.f1_score, 4);
  const avgLatencyVal = data?.average_detection_time_ms ?? (data as any)?.avg_time_ms;
  const avgLatencyDisplay = typeof avgLatencyVal === 'number'
    ? Number(avgLatencyVal ?? 0).toFixed(2)
    : safeToFixed(avgLatencyVal, 2);
  const avgRiskScoreDisplay = typeof data?.average_risk_score === 'number'
    ? Number(data.average_risk_score ?? 0).toFixed(2)
    : safeToFixed(data?.average_risk_score, 2);

  const breakdownEntries = Object.entries(data?.attack_type_breakdown || {});

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-2xl font-bold text-cyber-primary">Defensive Performance Evaluation</h2>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-navy text-cyan border border-cyan/30">
              DETERMINISTIC BENCHMARK
            </span>
          </div>
          <p className="text-cyber-secondary text-sm mt-1">
            Empirical evaluation of detection rates, confusion matrices, and precision-recall metrics computed from real database records.
          </p>
        </div>

        <button
          onClick={fetchPerformance}
          disabled={isRefreshing}
          className="flex items-center space-x-2 bg-navy hover:bg-navy-light text-cyan px-4 py-2.5 rounded-xl font-semibold shadow-md transition-all text-sm shrink-0 border border-cyan/20 disabled:opacity-50"
        >
          <RefreshCw size={16} className={isRefreshing ? 'animate-spin' : ''} />
          <span>Refresh Benchmark</span>
        </button>
      </div>

      {/* Error / Fallback Banner */}
      {errorMessage && (
        <div className="p-4 bg-amber-50 border border-amber-200 rounded-xl text-xs text-amber-900 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertCircle size={16} className="text-amber-600 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button
            onClick={fetchPerformance}
            className="underline font-bold text-amber-800 hover:text-amber-950 ml-4 shrink-0"
          >
            Retry
          </button>
        </div>
      )}

      {/* Primary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm">
          <p className="text-xs font-bold text-cyber-secondary uppercase tracking-wider">Detection Rate</p>
          <p className="text-3xl font-extrabold text-emerald-600 mt-2">
            {detectionRateDisplay}
          </p>
          <p className="text-xs text-cyber-secondary mt-1">
            {data?.detected_simulations ?? 0} of {data?.total_simulations ?? 0} attacks detected
          </p>
        </div>

        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm">
          <p className="text-xs font-bold text-cyber-secondary uppercase tracking-wider">F1-Score</p>
          <p className="text-3xl font-extrabold text-cyan-hover mt-2">
            {f1ScoreDisplay}
          </p>
          <p className="text-xs text-cyber-secondary mt-1">Harmonic mean of precision & recall</p>
        </div>

        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm">
          <p className="text-xs font-bold text-cyber-secondary uppercase tracking-wider">Avg Latency</p>
          <p className="text-3xl font-extrabold text-cyber-primary mt-2">
            {avgLatencyDisplay} <span className="text-base font-medium">ms</span>
          </p>
          <p className="text-xs text-cyber-secondary mt-1">Attack simulation response time</p>
        </div>

        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm">
          <p className="text-xs font-bold text-cyber-secondary uppercase tracking-wider">Average Risk Score</p>
          <p className="text-3xl font-extrabold text-slate-800 mt-2">
            {avgRiskScoreDisplay} <span className="text-base font-medium">/ 100</span>
          </p>
          <p className="text-xs text-cyber-secondary mt-1">Across all evaluated attacks</p>
        </div>
      </div>

      {/* Confusion Matrix & Statistical Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Confusion Matrix */}
        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-4">
          <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wider">
            Empirical Confusion Matrix
          </h3>
          <p className="text-xs text-cyber-secondary">
            Ground-truth simulated attacks vs. Q-SHIELD multi-layer detection outcomes.
          </p>

          <div className="grid grid-cols-2 gap-3 text-center">
            <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-xl">
              <p className="text-[11px] font-bold text-emerald-800 uppercase">True Positives (TP)</p>
              <p className="text-2xl font-mono font-extrabold text-emerald-700 mt-1">{data?.true_positives ?? 0}</p>
              <p className="text-[10px] text-emerald-600 mt-0.5">Attacks correctly caught</p>
            </div>
            <div className="p-4 bg-red-50 border border-red-200 rounded-xl">
              <p className="text-[11px] font-bold text-red-800 uppercase">False Negatives (FN)</p>
              <p className="text-2xl font-mono font-extrabold text-red-700 mt-1">{data?.false_negatives ?? 0}</p>
              <p className="text-[10px] text-red-600 mt-0.5">Attacks missed</p>
            </div>
            <div className="p-4 bg-amber-50 border border-amber-200 rounded-xl">
              <p className="text-[11px] font-bold text-amber-800 uppercase">False Positives (FP)</p>
              <p className="text-2xl font-mono font-extrabold text-amber-700 mt-1">{data?.false_positives ?? 0}</p>
              <p className="text-[10px] text-amber-600 mt-0.5">Authentic flagged as threat</p>
            </div>
            <div className="p-4 bg-blue-50 border border-blue-200 rounded-xl">
              <p className="text-[11px] font-bold text-blue-800 uppercase">True Negatives (TN)</p>
              <p className="text-2xl font-mono font-extrabold text-blue-700 mt-1">{data?.true_negatives ?? 0}</p>
              <p className="text-[10px] text-blue-600 mt-0.5">Authentic confirmed safe</p>
            </div>
          </div>
        </div>

        {/* Statistical Performance Breakdown */}
        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-4">
          <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wider">
            Defensive Classification Metrics
          </h3>
          <p className="text-xs text-cyber-secondary">
            Standard statistical ratios evaluated with safe zero-denominator handling.
          </p>

          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs font-bold mb-1">
                <span className="text-slate-700">Accuracy (TP + TN) / Total</span>
                <span className="text-emerald-600">{safeRatioToPercent(data?.accuracy, 1)}</span>
              </div>
              <div className="w-full h-2.5 bg-slate-100 rounded-full overflow-hidden">
                <div className="h-full bg-emerald-500 rounded-full transition-all duration-500" style={{ width: safeProgressWidth(data?.accuracy) }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-bold mb-1">
                <span className="text-slate-700">Precision TP / (TP + FP)</span>
                <span className="text-blue-600">{safeRatioToPercent(data?.precision, 1)}</span>
              </div>
              <div className="w-full h-2.5 bg-slate-100 rounded-full overflow-hidden">
                <div className="h-full bg-blue-500 rounded-full transition-all duration-500" style={{ width: safeProgressWidth(data?.precision) }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-bold mb-1">
                <span className="text-slate-700">Recall (Sensitivity) TP / (TP + FN)</span>
                <span className="text-cyan-hover">{safeRatioToPercent(data?.recall, 1)}</span>
              </div>
              <div className="w-full h-2.5 bg-slate-100 rounded-full overflow-hidden">
                <div className="h-full bg-cyan rounded-full transition-all duration-500" style={{ width: safeProgressWidth(data?.recall) }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-bold mb-1">
                <span className="text-slate-700">F1-Score</span>
                <span className="text-purple-600">{safeRatioToPercent(data?.f1_score, 1)}</span>
              </div>
              <div className="w-full h-2.5 bg-slate-100 rounded-full overflow-hidden">
                <div className="h-full bg-purple-500 rounded-full transition-all duration-500" style={{ width: safeProgressWidth(data?.f1_score) }} />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Attack Type Breakdown Table */}
      <div className="bg-white rounded-2xl border border-cyber-border shadow-sm overflow-hidden">
        <div className="p-6 border-b border-cyber-border">
          <h3 className="section-title">Attack-Specific Detection Breakdown</h3>
          <p className="text-xs text-cyber-secondary mt-0.5">
            Granular detection rates across each simulated attack vector.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-cyber-bg border-b border-cyber-border text-xs font-bold text-cyber-secondary uppercase">
                <th className="py-4 px-6">Attack Type</th>
                <th className="py-4 px-6">Total Runs</th>
                <th className="py-4 px-6">Detected</th>
                <th className="py-4 px-6">Missed</th>
                <th className="py-4 px-6">Detection Rate</th>
                <th className="py-4 px-6">Avg Detection Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border text-sm">
              {breakdownEntries.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-cyber-secondary text-sm">
                    No attack simulation records available. Run controlled attack simulations to populate granular benchmarks.
                  </td>
                </tr>
              ) : (
                breakdownEntries.map(([type, stats]: [string, any]) => {
                  const totalRuns = Number(stats?.total ?? 0);
                  const detected = Number(stats?.detected ?? 0);
                  const missed = Number(stats?.missed ?? 0);
                  const rate = stats?.detection_rate;
                  const avgTime = stats?.average_detection_time_ms ?? stats?.avg_time_ms ?? stats?.average_time_ms;

                  const rateFormatted = typeof rate === 'number'
                    ? `${Number(rate ?? 0).toFixed(2)}%`
                    : safeToPercent(rate, 2);
                  const avgTimeFormatted = typeof avgTime === 'number'
                    ? `${Number(avgTime ?? 0).toFixed(2)} ms`
                    : (avgTime !== null && avgTime !== undefined && !isNaN(Number(avgTime))
                      ? `${Number(avgTime ?? 0).toFixed(2)} ms`
                      : 'N/A');

                  const isHighRate = typeof rate === 'number' ? rate >= 80 : false;

                  return (
                    <tr key={type} className="hover:bg-slate-50 transition-colors">
                      <td className="py-4 px-6 font-semibold text-cyber-primary font-mono text-xs">{type}</td>
                      <td className="py-4 px-6 font-mono text-xs">{totalRuns}</td>
                      <td className="py-4 px-6 font-mono text-xs text-emerald-600 font-bold">{detected}</td>
                      <td className="py-4 px-6 font-mono text-xs text-red-600 font-bold">{missed}</td>
                      <td className="py-4 px-6">
                        <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-bold ${
                          rateFormatted === 'N/A'
                            ? 'bg-slate-100 text-slate-600'
                            : isHighRate
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                            : 'bg-amber-50 text-amber-700 border border-amber-200'
                        }`}>
                          {rateFormatted}
                        </span>
                      </td>
                      <td className="py-4 px-6 font-mono text-xs text-slate-600">
                        {avgTimeFormatted}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Scientific Disclaimer */}
      <div className="p-4 bg-blue-50/70 border border-blue-200 rounded-xl text-xs text-blue-900 flex items-start space-x-3">
        <Info size={18} className="text-blue-700 shrink-0 mt-0.5" />
        <div>
          <p className="font-bold">Evaluation Methodology & Integrity Notice:</p>
          <p className="mt-0.5">
            {data?.disclaimer ||
              'Performance metrics are calculated deterministically from controlled simulations and labeled test data without AI or machine learning.'}
          </p>
        </div>
      </div>
    </div>
  );
};

export default PerformanceEvaluationPage;
