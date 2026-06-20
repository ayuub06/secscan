import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

export default function Navbar() {
  const { user, logout } = useAuth()

  return (
    <nav className="no-print bg-white border-b border-gray-200 px-6 py-3 flex items-center justify-between">
      <Link to="/dashboard" className="flex items-center gap-2 text-gray-900 no-underline">
        <svg className="w-6 h-6 text-blue-600" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
        </svg>
        <span className="font-bold text-lg tracking-tight">SecScan</span>
      </Link>
      {user && (
        <div className="flex items-center gap-4">
          <span className="text-sm text-gray-500">{user.email}</span>
          <button
            onClick={logout}
            className="text-sm text-gray-600 hover:text-gray-900 px-3 py-1.5 rounded-md border border-gray-300 hover:border-gray-400 transition-colors"
          >
            Sign out
          </button>
        </div>
      )}
    </nav>
  )
}
