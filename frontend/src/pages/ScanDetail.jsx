import { useEffect, useRef, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import Navbar from '../components/Navbar.jsx'
import { api } from '../api/client.js'

const SEV_META = {
  5: { label: 'CRITICAL', bg: 'bg-red-600',    text: 'text-white',  border: '#dc2626', badgeCls: 'bg-red-100 text-red-700'   },
  4: { label: 'HIGH',     bg: 'bg-orange-600',  text: 'text-white',  border: '#ea580c', badgeCls: 'bg-orange-100 text-orange-700' },
  3: { label: 'MEDIUM',   bg: 'bg-amber-500',   text: 'text-white',  border: '#d97706', badgeCls: 'bg-amber-100 text-amber-700'  },
  2: { label: 'LOW',      bg: 'bg-lime-600',    text: 'text-white',  border: '#65a30d', badgeCls: 'bg-lime-100 text-lime-700'    },
  1: { label: 'INFO',     bg: 'bg-cyan-600',    text: 'text-white',  border: '#0891b2', badgeCls: 'bg-cyan-100 text-cyan-700'    },
}

const SEV_LABEL_TO_INT = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 }

function sevInt(finding) {
  if (typeof finding.severity === 'number') return finding.severity
  return SEV_LABEL_TO_INT[String(finding.severity).toUpperCase()] ?? 0
}

function fmtDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function SummaryBox({ label, count, bgCls, textCls }) {
  return (
    <div className={`rounded-xl px-5 py-4 text-center ${bgCls}`}>
      <p className={`text-3xl font-bold ${textCls}`}>{count ?? 0}</p>
      <p className={`text-xs font-semibold mt-1 tracking-wide ${textCls} opacity-90`}>{label}</p>
    </div>
  )
}

function FindingCard({ f }) {
  const sev = sevInt(f)
  const meta = SEV_META[sev] || SEV_META[1]

  const targetStr = [f.target, f.port ? `:${f.port}` : ''].join('')

  return (
    <div
      className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden mb-4"
      style={{ borderLeft: `4px solid ${meta.border}` }}
    >
      <div className="px-5 py-4">
        <div className="flex items-start justify-between gap-3 mb-2">
          <h3 className="text-base font-semibold text-gray-900">{f.title}</h3>
          <span className={`flex-shrink-0 px-2 py-0.5 rounded-full text-xs font-semibold ${meta.badgeCls}`}>
            {meta.label}
          </span>
        </div>

        {targetStr && (
          <p className="text-sm font-mono text-gray-500 mb-2">{targetStr}</p>
        )}

        <p className="text-sm text-gray-700 mb-4">{f.description}</p>

        {f.evidence && (
          <div className="mb-3">
            <p className="text-xs font-medium text-gray-400 mb-1">Evidence</p>
            <div className="bg-gray-100 rounded-lg px-4 py-3 font-mono text-xs text-gray-700 whitespace-pre-wrap break-all">
              {f.evidence}
            </div>
          </div>
        )}

        {f.remediation && (
          <div className="mb-3">
            <p className="text-xs font-medium text-green-600 mb-1">Remediation</p>
            <div className="bg-green-50 border-l-4 border-green-500 rounded-r-lg px-4 py-3 text-sm text-gray-700">
              {f.remediation}
            </div>
          </div>
        )}

        {f.cve_ids && f.cve_ids.length > 0 && (
          <div className="flex flex-wrap gap-2 mb-3">
            {f.cve_ids.map(cve => (
              <a
                key={cve}
                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                target="_blank"
                rel="noopener noreferrer"
                className="px-2 py-0.5 rounded bg-blue-100 text-blue-700 text-xs font-mono hover:bg-blue-200 transition-colors"
              >
                {cve}
              </a>
            ))}
          </div>
        )}

        <p className="text-xs text-gray-400">Discovered {fmtDate(f.discovered_at)}</p>
      </div>
    </div>
  )
}

export default function ScanDetail() {
  const { id }  = useParams()
  const pollRef = useRef(null)

  const [scan, setScan]     = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState(null)

  useEffect(() => {
    loadScan()
    return () => { if (pollRef.current) clearTimeout(pollRef.current) }
  }, [id])

  async function loadScan() {
    try {
      const data = await api.getScan(id)
      setScan(data)
      setLoading(false)
      if (data.status === 'pending' || data.status === 'running') {
        pollRef.current = setTimeout(loadScan, 3000)
      }
    } catch (e) {
      setError(e.message)
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50">
        <Navbar />
        <div className="flex items-center justify-center py-32">
          <div className="text-center">
            <div className="w-12 h-12 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
            <p className="text-gray-500">Loading scan…</p>
          </div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50">
        <Navbar />
        <div className="max-w-4xl mx-auto px-6 py-10">
          <div className="bg-red-50 border border-red-200 text-red-700 rounded-xl px-5 py-4 text-sm">{error}</div>
        </div>
      </div>
    )
  }

  /* ── In-progress ── */
  if (scan.status === 'pending' || scan.status === 'running') {
    return (
      <div className="min-h-screen bg-gray-50">
        <Navbar />
        <div className="flex items-center justify-center py-32">
          <div className="text-center">
            <div className="w-12 h-12 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
            <p className="text-lg font-medium text-gray-700">Scan in progress…</p>
            <p className="text-sm text-gray-400 mt-1">Status: <span className="font-medium">{scan.status}</span> — checking every 3 seconds</p>
          </div>
        </div>
      </div>
    )
  }

  /* ── Failed ── */
  if (scan.status === 'failed') {
    return (
      <div className="min-h-screen bg-gray-50">
        <Navbar />
        <div className="max-w-4xl mx-auto px-6 py-10">
          <div className="bg-red-50 border border-red-200 rounded-xl p-6">
            <h2 className="font-semibold text-red-800 mb-3">Scan Failed</h2>
            <dl className="text-sm space-y-2">
              <div><dt className="text-red-600 font-medium">Scan ID</dt><dd className="font-mono text-red-800">{scan.scan_id}</dd></div>
              <div><dt className="text-red-600 font-medium">Started</dt><dd className="text-red-800">{fmtDate(scan.started_at)}</dd></div>
              {scan.error_message && (
                <div><dt className="text-red-600 font-medium">Error</dt><dd className="text-red-800">{scan.error_message}</dd></div>
              )}
            </dl>
          </div>
        </div>
      </div>
    )
  }

  /* ── Completed ── */
  const result   = scan.result || {}
  const summary  = result.summary || {}
  const findings = (result.findings || []).slice().sort((a, b) => sevInt(b) - sevInt(a))
  const checksRun = Array.isArray(result.checks_run)
    ? result.checks_run.join(', ')
    : (result.checks_run || '—')

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="max-w-4xl mx-auto px-6 py-10 print-full">

        {/* Print / PDF button */}
        <div className="flex justify-end mb-6 no-print">
          <button
            onClick={() => window.print()}
            className="flex items-center gap-2 text-sm text-gray-600 hover:text-gray-900 border border-gray-300 hover:border-gray-400 px-4 py-2 rounded-xl transition-colors"
          >
            <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M5 4v3H4a2 2 0 00-2 2v3a2 2 0 002 2h1v2a2 2 0 002 2h6a2 2 0 002-2v-2h1a2 2 0 002-2V9a2 2 0 00-2-2h-1V4a2 2 0 00-2-2H7a2 2 0 00-2 2zm8 0H7v3h6V4zm0 8H7v4h6v-4z" clipRule="evenodd"/>
            </svg>
            Download as PDF
          </button>
        </div>

        {/* Report header */}
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-8 mb-6">
          <div className="flex items-start justify-between mb-6">
            <div>
              <h1 className="text-2xl font-bold text-gray-900 mb-1">Security Scan Report</h1>
              <p className="text-sm text-gray-500">Generated by SecScan automated scanner</p>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-100 text-green-700 text-xs font-medium">
              ✓ Completed
            </div>
          </div>
          <dl className="grid sm:grid-cols-2 gap-3 text-sm">
            <div>
              <dt className="text-gray-400 text-xs font-medium mb-0.5">Scan ID</dt>
              <dd className="font-mono text-gray-700 text-xs break-all">{scan.scan_id}</dd>
            </div>
            <div>
              <dt className="text-gray-400 text-xs font-medium mb-0.5">Target</dt>
              <dd className="font-mono text-gray-700">{result.scope || '—'}</dd>
            </div>
            <div>
              <dt className="text-gray-400 text-xs font-medium mb-0.5">Authorized by</dt>
              <dd className="text-gray-700">{result.authorized_by || '—'}</dd>
            </div>
            <div>
              <dt className="text-gray-400 text-xs font-medium mb-0.5">Checks run</dt>
              <dd className="text-gray-700">{checksRun}</dd>
            </div>
            <div>
              <dt className="text-gray-400 text-xs font-medium mb-0.5">Started</dt>
              <dd className="text-gray-700">{fmtDate(scan.started_at)}</dd>
            </div>
            <div>
              <dt className="text-gray-400 text-xs font-medium mb-0.5">Completed</dt>
              <dd className="text-gray-700">{fmtDate(scan.completed_at)}</dd>
            </div>
          </dl>
        </div>

        {/* Summary */}
        <div className="mb-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-3">Summary</h2>
          <div className="grid grid-cols-5 gap-3">
            <SummaryBox label="CRITICAL" count={summary.critical ?? summary.CRITICAL} bgCls="bg-red-600"    textCls="text-white" />
            <SummaryBox label="HIGH"     count={summary.high     ?? summary.HIGH}     bgCls="bg-orange-500" textCls="text-white" />
            <SummaryBox label="MEDIUM"   count={summary.medium   ?? summary.MEDIUM}   bgCls="bg-amber-500"  textCls="text-white" />
            <SummaryBox label="LOW"      count={summary.low      ?? summary.LOW}      bgCls="bg-lime-600"   textCls="text-white" />
            <SummaryBox label="INFO"     count={summary.info     ?? summary.INFO}     bgCls="bg-cyan-600"   textCls="text-white" />
          </div>
        </div>

        {/* Findings */}
        <div className="mb-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-3">
            Findings <span className="text-sm font-normal text-gray-400">({findings.length})</span>
          </h2>
          {findings.length === 0 ? (
            <div className="bg-green-50 border border-green-200 rounded-xl px-6 py-8 text-center text-green-700">
              <svg className="w-10 h-10 mx-auto mb-3 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd"/>
              </svg>
              <p className="font-semibold">No findings detected — this target looks clean!</p>
            </div>
          ) : (
            findings.map((f, i) => <FindingCard key={f.id ?? i} f={f} />)
          )}
        </div>

        {/* Report footer */}
        <div className="bg-gray-50 border border-gray-200 rounded-xl px-6 py-4 text-center text-sm text-gray-400">
          <p className="font-medium text-gray-500 mb-1">Generated by SecScan automated scanner</p>
          <p>This report should be reviewed by a qualified security professional before acting on findings.</p>
          <p className="mt-1">Generated {fmtDate(scan.completed_at)}</p>
        </div>
      </div>
    </div>
  )
}
