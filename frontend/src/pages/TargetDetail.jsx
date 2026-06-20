import { useEffect, useRef, useState } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
import Navbar from '../components/Navbar.jsx'
import { api } from '../api/client.js'
import { useToast } from '../context/ToastContext.jsx'

function CopyField({ label, value }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <div className="mb-3">
      <p className="text-xs font-medium text-gray-500 mb-1">{label}</p>
      <div className="flex items-center gap-2">
        <code className="flex-1 bg-gray-100 text-gray-800 text-xs px-3 py-2 rounded-lg font-mono break-all">
          {value}
        </code>
        <button
          onClick={copy}
          className="flex-shrink-0 text-xs px-3 py-2 rounded-lg border border-gray-300 hover:border-blue-400 text-gray-600 hover:text-blue-600 transition-colors"
        >
          {copied ? '✓ Copied' : 'Copy'}
        </button>
      </div>
    </div>
  )
}

function ScanStatusBadge({ status }) {
  const map = {
    completed: 'bg-green-100 text-green-700',
    running:   'bg-blue-100 text-blue-700',
    pending:   'bg-amber-100 text-amber-700',
    failed:    'bg-red-100 text-red-700',
  }
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${map[status] || 'bg-gray-100 text-gray-600'}`}>
      {status}
    </span>
  )
}

function fmtDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

export default function TargetDetail() {
  const { id }    = useParams()
  const navigate  = useNavigate()
  const toast     = useToast()
  const pollRef   = useRef(null)

  const [target, setTarget]           = useState(null)
  const [verInfo, setVerInfo]         = useState(null)
  const [loading, setLoading]         = useState(true)
  const [error, setError]             = useState(null)

  const [dnsChecking, setDnsChecking] = useState(false)
  const [dnsResult, setDnsResult]     = useState(null)  // null | 'ok' | 'pending'
  const [fileChecking, setFileChecking] = useState(false)
  const [fileResult, setFileResult]   = useState(null)

  const [scanning, setScanning]       = useState(false)
  const [pollStatus, setPollStatus]   = useState(null)
  const [activeScanId, setActiveScanId] = useState(null)

  useEffect(() => {
    Promise.all([api.getTarget(id), api.getVerificationInfo(id)])
      .then(([t, v]) => { setTarget(t); setVerInfo(v) })
      .catch(e => setError(e))
      .finally(() => setLoading(false))
  }, [id])

  useEffect(() => {
    return () => { if (pollRef.current) clearTimeout(pollRef.current) }
  }, [])

  async function checkVerification(method, setChecking, setResult) {
    setChecking(true)
    setResult(null)
    try {
      const res = await api.verifyTarget(id, method)
      if (res.verified) {
        setResult('ok')
        toast('Domain verified!')
        // Refresh target and verInfo
        const [t, v] = await Promise.all([api.getTarget(id), api.getVerificationInfo(id)])
        setTarget(t)
        setVerInfo(v)
      } else {
        setResult('pending')
      }
    } catch (e) {
      toast(e.message, 'error')
    } finally {
      setChecking(false)
    }
  }

  async function handleRunScan() {
    setScanning(true)
    setPollStatus('pending')
    try {
      const res = await api.triggerScan(id)
      const scanRunId = res.scan_run_id
      setActiveScanId(scanRunId)
      toast('Scan started')
      pollScan(scanRunId)
    } catch (e) {
      toast(e.message, 'error')
      setScanning(false)
      setPollStatus(null)
    }
  }

  function pollScan(scanRunId) {
    pollRef.current = setTimeout(async () => {
      try {
        const scan = await api.getScan(scanRunId)
        setPollStatus(scan.status)
        if (scan.status === 'pending' || scan.status === 'running') {
          pollScan(scanRunId)
        } else {
          setScanning(false)
          // Refresh scan history
          api.getTarget(id).then(t => setTarget(t)).catch(() => {})
        }
      } catch (_) {
        setScanning(false)
      }
    }, 3000)
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50">
        <Navbar />
        <div className="max-w-4xl mx-auto px-6 py-10 animate-pulse space-y-4">
          <div className="h-6 bg-gray-200 rounded w-48" />
          <div className="h-40 bg-gray-100 rounded-2xl" />
          <div className="h-40 bg-gray-100 rounded-2xl" />
        </div>
      </div>
    )
  }

  if (error) {
    const isForbidden = error.status === 403
    return (
      <div className="min-h-screen bg-gray-50">
        <Navbar />
        <div className="max-w-4xl mx-auto px-6 py-10">
          {isForbidden ? (
            <div className="bg-amber-50 border border-amber-200 rounded-xl px-5 py-6 text-sm">
              <p className="font-semibold text-amber-800 mb-1">Access denied</p>
              <p className="text-amber-700">You don&apos;t have access to this target. It may belong to a different account or be old test data.</p>
              <Link to="/dashboard" className="inline-block mt-4 text-blue-600 hover:underline font-medium">← Back to Clients</Link>
            </div>
          ) : (
            <div className="bg-red-50 border border-red-200 text-red-700 rounded-xl px-5 py-4 text-sm">{error.message}</div>
          )}
        </div>
      </div>
    )
  }

  const isVerified = target?.verified

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="max-w-4xl mx-auto px-6 py-10">
        {/* Breadcrumb */}
        <div className="mb-2 text-sm text-gray-500">
          <Link to="/dashboard" className="hover:text-gray-700">Clients</Link>
          {' / '}
          <Link to={`/clients/${target?.client_id}`} className="hover:text-gray-700">Client</Link>
          {' / '}
          <span className="text-gray-900">{target?.scope}</span>
        </div>

        <h1 className="text-2xl font-bold text-gray-900 mb-1">{target?.scope}</h1>

        {/* ── CASE A: Not yet verified ── */}
        {!isVerified && (
          <>
            <div className="bg-amber-50 border border-amber-200 rounded-xl px-5 py-4 mb-8 flex gap-3">
              <svg className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd"/>
              </svg>
              <div>
                <p className="font-semibold text-amber-800">Verification Required</p>
                <p className="text-sm text-amber-700 mt-0.5">You must confirm ownership of this domain before scanning. Choose one method below.</p>
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-6 mb-6">
              {/* DNS method */}
              <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-sm">
                <h2 className="font-semibold text-gray-900 mb-1">Method 1: DNS TXT Record</h2>
                <p className="text-sm text-gray-500 mb-4">Add the following TXT record to your domain's DNS settings. This may take a few minutes to propagate.</p>
                {verInfo?.dns_instructions ? (
                  <>
                    <CopyField label="Record Type" value={verInfo.dns_instructions.record_type} />
                    <CopyField label="Record Name" value={verInfo.dns_instructions.name} />
                    <CopyField label="Record Value" value={verInfo.dns_instructions.value} />
                  </>
                ) : (
                  <p className="text-sm text-gray-400">Verification info unavailable.</p>
                )}
                <button
                  onClick={() => checkVerification('dns', setDnsChecking, setDnsResult)}
                  disabled={dnsChecking}
                  className="mt-4 w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2.5 rounded-xl disabled:opacity-60 transition-colors"
                >
                  {dnsChecking && <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
                  {dnsChecking ? 'Checking…' : 'Check DNS Verification'}
                </button>
                {dnsResult === 'ok' && (
                  <p className="mt-3 text-sm text-green-600 font-medium text-center">✓ Verified via DNS!</p>
                )}
                {dnsResult === 'pending' && (
                  <p className="mt-3 text-sm text-amber-600 text-center">Not verified yet — DNS records can take a few minutes to propagate. Try again shortly.</p>
                )}
              </div>

              {/* File method */}
              <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-sm">
                <h2 className="font-semibold text-gray-900 mb-1">Method 2: File Upload</h2>
                <p className="text-sm text-gray-500 mb-4">Upload a file to your web server at the path shown below containing exactly the content shown.</p>
                {verInfo?.file_instructions ? (
                  <>
                    <CopyField label="File Path" value={verInfo.file_instructions.path} />
                    <CopyField label="File Content" value={verInfo.file_instructions.content} />
                  </>
                ) : (
                  <p className="text-sm text-gray-400">Verification info unavailable.</p>
                )}
                <button
                  onClick={() => checkVerification('file', setFileChecking, setFileResult)}
                  disabled={fileChecking}
                  className="mt-4 w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2.5 rounded-xl disabled:opacity-60 transition-colors"
                >
                  {fileChecking && <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
                  {fileChecking ? 'Checking…' : 'Check File Verification'}
                </button>
                {fileResult === 'ok' && (
                  <p className="mt-3 text-sm text-green-600 font-medium text-center">✓ Verified via file!</p>
                )}
                {fileResult === 'pending' && (
                  <p className="mt-3 text-sm text-amber-600 text-center">File not found yet — check the path and content, then try again.</p>
                )}
              </div>
            </div>

            <p className="text-sm text-gray-400 text-center">Both methods confirm you control this domain. You only need to succeed with one.</p>
          </>
        )}

        {/* ── CASE B: Verified ── */}
        {isVerified && (
          <>
            <div className="flex items-center gap-2 mb-6">
              <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-green-100 text-green-700 text-sm font-medium">
                <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd"/>
                </svg>
                Verified
              </span>
              <span className="text-sm text-gray-500">via {target.verification_method} on {fmtDate(target.verified_at)}</span>
            </div>

            {/* Target details */}
            <div className="bg-white rounded-2xl border border-gray-200 p-6 mb-6 shadow-sm">
              <h2 className="font-semibold text-gray-900 mb-4">Target Details</h2>
              <dl className="grid sm:grid-cols-2 gap-3 text-sm">
                <div>
                  <dt className="text-gray-500">Scope</dt>
                  <dd className="font-medium text-gray-900 font-mono mt-0.5">{target.scope}</dd>
                </div>
                <div>
                  <dt className="text-gray-500">Authorization Reference</dt>
                  <dd className="font-medium text-gray-900 mt-0.5">{target.authorized_by}</dd>
                </div>
                <div>
                  <dt className="text-gray-500">CVE Lookup</dt>
                  <dd className="font-medium text-gray-900 mt-0.5">{target.skip_cve ? 'Skipped' : 'Enabled'}</dd>
                </div>
                {target.schedule_cron && (
                  <div>
                    <dt className="text-gray-500">Schedule</dt>
                    <dd className="font-mono font-medium text-gray-900 mt-0.5">{target.schedule_cron}</dd>
                  </div>
                )}
              </dl>
            </div>

            {/* Scan trigger */}
            <div className="bg-white rounded-2xl border border-gray-200 p-6 mb-6 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-semibold text-gray-900">Run a Scan</h2>
                <button
                  onClick={handleRunScan}
                  disabled={scanning}
                  className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-medium px-5 py-2.5 rounded-xl text-sm disabled:opacity-60 transition-colors"
                >
                  {scanning && <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
                  {scanning ? 'Scanning…' : 'Run Scan Now'}
                </button>
              </div>

              {scanning && (
                <div className="bg-blue-50 border border-blue-200 rounded-xl px-4 py-3 text-sm text-blue-700">
                  Scan running — checking every 3 seconds… <span className="font-medium">Status: {pollStatus}</span>
                </div>
              )}
              {!scanning && pollStatus === 'completed' && activeScanId && (
                <div className="bg-green-50 border border-green-200 rounded-xl px-4 py-3 text-sm text-green-700 flex items-center justify-between">
                  <span>✓ Scan complete!</span>
                  <Link to={`/scans/${activeScanId}`} className="font-medium text-green-800 hover:underline">
                    View Report →
                  </Link>
                </div>
              )}
              {!scanning && pollStatus === 'failed' && (
                <div className="bg-red-50 border border-red-200 rounded-xl px-4 py-3 text-sm text-red-700">
                  Scan failed. Check the report for details.
                </div>
              )}
            </div>

            {/* Scan history */}
            <div className="bg-white rounded-2xl border border-gray-200 shadow-sm">
              <div className="px-6 py-4 border-b border-gray-100">
                <h2 className="font-semibold text-gray-900">Scan History</h2>
              </div>
              {(!target.scan_runs || target.scan_runs.length === 0) ? (
                <div className="px-6 py-12 text-center text-gray-400 text-sm">
                  No scans yet — run your first scan above.
                </div>
              ) : (
                <div className="divide-y divide-gray-100">
                  {target.scan_runs.map(run => (
                    <div
                      key={run.id}
                      onClick={() => navigate(`/scans/${run.id}`)}
                      className="px-6 py-4 flex items-center justify-between hover:bg-gray-50 cursor-pointer transition-colors"
                    >
                      <div className="flex items-center gap-4">
                        <code className="text-xs text-gray-500 font-mono">{(run.scan_id || run.id.toString()).slice(0, 8)}</code>
                        <ScanStatusBadge status={run.status} />
                      </div>
                      <div className="text-sm text-gray-500 text-right">
                        <p>{fmtDate(run.started_at)}</p>
                        {run.completed_at && (
                          <p className="text-xs text-gray-400">Done {fmtDate(run.completed_at)}</p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
