export const dynamic = 'force-dynamic'

import Link from 'next/link'

export default function NotFound() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-950 via-blue-950 to-slate-900 p-8">
      <div className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-2 border-orange-500/30 shadow-2xl backdrop-blur-sm max-w-2xl w-full rounded-xl">
        <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-orange-500 to-red-500 opacity-5 rounded-full -mr-32 -mt-32"></div>
        <div className="flex flex-col items-center justify-center py-28 px-8">
          <div className="p-10 rounded-3xl bg-gradient-to-br from-orange-500 via-red-500 to-pink-500 mb-10 shadow-2xl shadow-orange-500/30">
            <svg className="h-28 w-28 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h1 className="text-7xl font-black text-white mb-5">
            404
          </h1>
          <h2 className="text-4xl font-black text-white mb-5 text-center">
            Página no encontrada
          </h2>
          <p className="text-2xl text-orange-300 mb-12 font-semibold text-center">
            La página que buscas no existe o ha sido movida
          </p>
          <Link
            href="/dashboard"
            className="inline-flex items-center justify-center h-20 px-12 text-2xl font-black bg-gradient-to-r from-orange-600 via-red-600 to-pink-600 hover:from-orange-700 hover:via-red-700 hover:to-pink-700 text-white shadow-2xl shadow-orange-500/30 rounded-lg transition-all"
          >
            <svg className="mr-4 h-9 w-9" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
            </svg>
            Volver al inicio
          </Link>
        </div>
      </div>
    </div>
  )
}
