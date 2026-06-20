import { useEffect, useState } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
import Navbar from '../components/Navbar.jsx'
import { api } from '../api/client.js'
import { useToast } from '../context/ToastContext.jsx'

const EMPTY_FORM = {
  scope: '',
  authorized_by: '',
  skip_cve: false,
  schedule_cron: '',
}

function StatusBadge({ verified }) {
  return verified ? (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-700">
      <span className="w-1.5 h-1.5 rounded-full bg-green-500 inline-block"></span>Verified
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-700">
      <span className="w-1.5 h-1.5 rounded-full bg-amber-500 inline-block"></span>Pending
    </span>
  )
}

export default function ClientDetail() {
  const { id }     = useParams()
  const navigate   = useNavigate()
  const toast      = useToast()

  const [client, setClient]     = useState(null)
  const [targets, setTargets]   = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm]         = useState(EMPTY_FORM)
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError]   = useState(null)

  useEffect(() => {
    api.getClient(id)
      .then(data => {
        setClient(data)
        setTargets(data.targets || [])
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [id])

  async function handleAddTarget(e) {
    e.preventDefault()
    setFormError(null)
    setSubmitting(true)
    try {
      const target = await api.createTarget({ ...form, client_id: Number(id) })
      toast('Target added — complete verification to start scanning')
      navigate(`/targets/${target.id}`)
    } catch (e) {
      setFormError(e.message)
    } finally {
      setSubmitting(false)
    }
  }

  async function handleDeleteTarget(t) {
    if (!window.confirm(`Delete target "${t.scope}"? This cannot be undone.`)) return
    try {
      await api.deleteTarget(t.id)
      setTargets(prev => prev.filter(x => x.id !== t.id))
      toast('Target deleted')
    } catch (e) {
      toast(e.message, 'error')
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50">
        <Navbar />
        <div className="max-w-5xl mx-auto px-6 py-10">
          <div className="animate-pulse space-y-4">
            <div className="h-7 bg-gray-200 rounded w-48" />
            <div className="h-4 bg-gray-100 rounded w-64" />
            <div className="h-24 bg-gray-100 rounded-2xl mt-8" />
            <div className="h-24 bg-gray-100 rounded-2xl" />
          </div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50">
        <Navbar />
        <div className="max-w-5xl mx-auto px-6 py-10">
          <div className="bg-red-50 border border-red-200 text-red-700 rounded-xl px-5 py-4 text-sm">
            {error}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="max-w-5xl mx-auto px-6 py-10">
        {/* Header */}
        <div className="mb-2 text-sm text-gray-500">
          <Link to="/dashboard" className="hover:text-gray-700">Clients</Link>
          {' / '}
          <span className="text-gray-900">{client?.name}</span>
        </div>
        <div className="flex items-start justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">{client?.name}</h1>
            {client?.contact_email && (
              <p className="text-sm text-gray-500 mt-1">{client.contact_email}</p>
            )}
          </div>
          <button
            onClick={() => setShowForm(s => !s)}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-medium px-4 py-2.5 rounded-xl text-sm transition-colors"
          >
            <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clipRule="evenodd"/>
            </svg>
            Add Target
          </button>
        </div>

        {/* Add target form */}
        {showForm && (
          <form onSubmit={handleAddTarget} className="bg-white rounded-2xl border border-gray-200 p-6 mb-6 shadow-sm">
            <h2 className="font-semibold text-gray-900 mb-4">Add Scan Target</h2>
            {formError && (
              <div className="bg-red-50 border border-red-200 text-red-700 rounded-lg px-4 py-3 mb-4 text-sm">
                {formError}
              </div>
            )}
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Scope * <span className="text-gray-400 font-normal">(domain or IP)</span>
                </label>
                <input
                  required
                  value={form.scope}
                  onChange={e => setForm(d => ({ ...d, scope: e.target.value }))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="example.com"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Authorization Reference *
                </label>
                <input
                  required
                  value={form.authorized_by}
                  onChange={e => setForm(d => ({ ...d, authorized_by: e.target.value }))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g. email confirmation, ticket ID, signed agreement"
                />
                <p className="text-xs text-gray-400 mt-1">Reference confirming you have permission to scan this target.</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Schedule <span className="text-gray-400 font-normal">(optional cron expression)</span>
                </label>
                <input
                  value={form.schedule_cron}
                  onChange={e => setForm(d => ({ ...d, schedule_cron: e.target.value }))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="0 2 * * 1  (every Monday at 2am)"
                />
                <p className="text-xs text-gray-400 mt-1">Leave blank for manual-only scans.</p>
              </div>
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={form.skip_cve}
                  onChange={e => setForm(d => ({ ...d, skip_cve: e.target.checked }))}
                  className="w-4 h-4 text-blue-600 rounded"
                />
                <span className="text-sm text-gray-700">Skip CVE lookup <span className="text-gray-400">(faster scan, no CVE matching)</span></span>
              </label>
            </div>
            <div className="flex gap-2 justify-end mt-5">
              <button
                type="button"
                onClick={() => { setShowForm(false); setFormError(null); setForm(EMPTY_FORM) }}
                className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900 border border-gray-300 rounded-lg"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-lg disabled:opacity-50"
              >
                {submitting ? 'Adding…' : 'Add Target'}
              </button>
            </div>
          </form>
        )}

        {/* Targets list */}
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Targets</h2>
        {targets.length === 0 ? (
          <div className="text-center py-16 bg-white rounded-2xl border border-gray-200">
            <p className="text-gray-500 mb-4">No targets yet — add one to start scanning.</p>
            <button
              onClick={() => setShowForm(true)}
              className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-medium px-5 py-2.5 rounded-xl text-sm"
            >
              Add Target
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            {targets.map(t => (
              <div key={t.id} className="bg-white rounded-2xl border border-gray-200 px-6 py-4 flex items-center justify-between hover:border-blue-300 transition-colors group">
                <div className="flex items-center gap-4 min-w-0">
                  <div className="min-w-0">
                    <p className="font-medium text-gray-900 truncate">{t.scope}</p>
                    <p className="text-xs text-gray-400 mt-0.5 truncate">Auth: {t.authorized_by}</p>
                  </div>
                  <StatusBadge verified={t.verified} />
                </div>
                <div className="flex items-center gap-2 flex-shrink-0 ml-4">
                  <Link
                    to={`/targets/${t.id}`}
                    className="text-sm text-blue-600 hover:text-blue-800 font-medium px-3 py-1.5 rounded-lg hover:bg-blue-50 transition-colors"
                  >
                    View
                  </Link>
                  <button
                    onClick={() => handleDeleteTarget(t)}
                    className="w-7 h-7 flex items-center justify-center rounded-full text-gray-400 hover:text-red-500 hover:bg-red-50 transition-colors opacity-0 group-hover:opacity-100"
                    title="Delete target"
                  >
                    ×
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
