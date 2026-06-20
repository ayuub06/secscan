import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

const CHECKS = [
  {
    title: 'Port Scan',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
      </svg>
    ),
    desc: 'Identifies open TCP/UDP ports and running services. Exposed ports are the first thing attackers probe — know yours before they do.',
  },
  {
    title: 'TLS / Certificate',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    ),
    desc: 'Checks TLS protocol versions, cipher suites, certificate expiry, and chain validity. Expired or weak TLS silently breaks trust.',
  },
  {
    title: 'HTTP Security Headers',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M9 12h6M9 16h6M9 8h6M5 3h14a2 2 0 012 2v14a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2z"/>
      </svg>
    ),
    desc: 'Verifies presence of CSP, HSTS, X-Frame-Options, and other defensive headers. Missing headers enable XSS and clickjacking attacks.',
  },
  {
    title: 'DNS Configuration',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/>
      </svg>
    ),
    desc: 'Checks SPF, DKIM, DMARC records and zone transfer settings. Misconfigured DNS enables email spoofing and subdomain takeover.',
  },
  {
    title: 'Exposed Admin Panels',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>
      </svg>
    ),
    desc: 'Probes common admin paths (/admin, /wp-admin, /phpmyadmin, etc.). Publicly reachable admin panels are a high-value target for credential stuffing.',
  },
  {
    title: 'Known CVEs',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
    ),
    desc: 'Matches detected service banners against the NVD CVE database. Unpatched known vulnerabilities are the most commonly exploited attack vector.',
  },
]

const STEPS = [
  {
    n: '1',
    title: 'Sign in and add your domain',
    desc: 'Log in with Google and create a client profile. Then add the domain or IP range you want to assess.',
  },
  {
    n: '2',
    title: 'Verify ownership',
    desc: 'Prove you control the target by adding a DNS TXT record or uploading a verification file. SecScan will never scan a domain you don\'t own.',
  },
  {
    n: '3',
    title: 'Scan and get a detailed report',
    desc: 'Trigger a scan with one click. Results include severity-ranked findings, evidence, and specific remediation guidance.',
  },
]

export default function Landing() {
  const { user, loading } = useAuth()

  if (loading) return null
  if (user) return <Navigate to="/dashboard" replace />

  return (
    <div className="min-h-screen bg-white text-gray-900 font-sans">
      {/* Navbar */}
      <header className="border-b border-gray-200 px-6 py-4 flex items-center justify-between max-w-6xl mx-auto">
        <div className="flex items-center gap-2">
          <svg className="w-7 h-7 text-blue-600" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
          </svg>
          <span className="text-xl font-bold tracking-tight">SecScan</span>
        </div>
        <a
          href="http://localhost:5000/api/auth/google/login"
          className="flex items-center gap-2 px-4 py-2 rounded-lg border border-gray-300 hover:border-gray-400 text-sm font-medium text-gray-700 hover:text-gray-900 transition-colors bg-white shadow-sm"
        >
          <svg className="w-4 h-4" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
          </svg>
          Sign in with Google
        </a>
      </header>

      {/* Hero */}
      <section className="max-w-6xl mx-auto px-6 py-24 text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-blue-50 text-blue-700 text-xs font-medium mb-6 border border-blue-200">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-500 inline-block"></span>
          Automated security scanning with ownership verification
        </div>
        <h1 className="text-5xl md:text-6xl font-bold tracking-tight text-gray-900 leading-tight mb-6">
          Know What's Exposed<br />
          <span className="text-blue-600">Before Attackers Do</span>
        </h1>
        <p className="text-xl text-gray-600 max-w-2xl mx-auto mb-10 leading-relaxed">
          SecScan automatically checks your domains and servers for open ports, weak TLS,
          missing security headers, DNS misconfigurations, exposed admin panels, and known CVEs.
          Get a prioritised, evidence-backed report in minutes.
        </p>
        <a
          href="http://localhost:5000/api/auth/google/login"
          className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold px-8 py-4 rounded-xl text-lg transition-colors shadow-md hover:shadow-lg"
        >
          Start Free Scan
          <svg className="w-5 h-5" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M10.293 5.293a1 1 0 011.414 0l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414-1.414L12.586 11H5a1 1 0 110-2h7.586l-2.293-2.293a1 1 0 010-1.414z" clipRule="evenodd"/>
          </svg>
        </a>
        <p className="mt-4 text-sm text-gray-400">No credit card required. Domain ownership verification required before any scan.</p>
      </section>

      {/* How it works */}
      <section className="bg-gray-50 py-20">
        <div className="max-w-6xl mx-auto px-6">
          <h2 className="text-3xl font-bold text-center text-gray-900 mb-4">How it works</h2>
          <p className="text-center text-gray-500 mb-12">Three steps from sign-up to actionable security report.</p>
          <div className="grid md:grid-cols-3 gap-8">
            {STEPS.map(step => (
              <div key={step.n} className="bg-white rounded-2xl p-8 shadow-sm border border-gray-100 text-center">
                <div className="w-12 h-12 bg-blue-600 text-white rounded-full flex items-center justify-center text-xl font-bold mx-auto mb-4">
                  {step.n}
                </div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">{step.title}</h3>
                <p className="text-gray-500 text-sm leading-relaxed">{step.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* What we check */}
      <section className="py-20">
        <div className="max-w-6xl mx-auto px-6">
          <h2 className="text-3xl font-bold text-center text-gray-900 mb-4">What we check</h2>
          <p className="text-center text-gray-500 mb-12">Six independent checks, each targeting a distinct attack surface.</p>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {CHECKS.map(c => (
              <div key={c.title} className="rounded-2xl border border-gray-200 p-6 hover:border-blue-300 hover:shadow-md transition-all">
                <div className="text-blue-600 mb-4">{c.icon}</div>
                <h3 className="font-semibold text-gray-900 mb-2">{c.title}</h3>
                <p className="text-sm text-gray-500 leading-relaxed">{c.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA band */}
      <section className="bg-blue-600 py-16">
        <div className="max-w-2xl mx-auto px-6 text-center">
          <h2 className="text-3xl font-bold text-white mb-4">Ready to find what's exposed?</h2>
          <p className="text-blue-100 mb-8">Sign in and run your first scan in under five minutes.</p>
          <a
            href="http://localhost:5000/api/auth/google/login"
            className="inline-flex items-center gap-2 bg-white text-blue-600 font-semibold px-8 py-4 rounded-xl text-lg hover:bg-blue-50 transition-colors"
          >
            Get started — it's free
          </a>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-200 py-8 text-center text-sm text-gray-400">
        <div className="max-w-6xl mx-auto px-6">
          <p className="font-medium text-gray-600 mb-1">SecScan — automated security scanning</p>
          <p>All scans require domain ownership verification. SecScan will never scan assets you don't control.</p>
        </div>
      </footer>
    </div>
  )
}
