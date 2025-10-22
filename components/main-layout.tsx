'use client'

import { Header } from '@/components/header'

interface MainLayoutProps {
  children: React.ReactNode
}

export function MainLayout({ children }: MainLayoutProps) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-blue-950 to-slate-900">
      {/* Efectos de fondo */}
      <div className="fixed inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(16,185,129,0.05),transparent_50%)]"></div>
      <div className="fixed inset-0 bg-[radial-gradient(circle_at_80%_20%,rgba(139,92,246,0.1),transparent_50%)]"></div>
      <div className="fixed inset-0 bg-[radial-gradient(circle_at_20%_80%,rgba(6,182,212,0.08),transparent_50%)]"></div>

      <div className="relative z-10">
        <Header />
        <main className="w-full px-6 py-10">
          {children}
        </main>
      </div>
    </div>
  )
}
