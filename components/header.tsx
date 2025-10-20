'use client'

import { useState } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { Button } from '@/components/ui/button'
import Image from 'next/image'
import {
  LayoutDashboard,
  Building2,
  User,
  BarChart3,
  LogOut,
  Wallet
} from 'lucide-react'

export function Header() {
  const pathname = usePathname()
  const router = useRouter()
  const { user, signOut } = useAuth()
  const [logoError, setLogoError] = useState(false)

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
    { name: 'Empresas', href: '/empresas', icon: Building2 },
    { name: 'Personal', href: '/personal', icon: User },
    { name: 'Análisis', href: '/analisis', icon: BarChart3 },
  ]

  const handleLogout = async () => {
    await signOut()
    router.push('/auth/login')
  }

  const isActive = (href: string) => {
    if (href === '/dashboard') return pathname === href
    return pathname.startsWith(href)
  }

  if (!user) return null

  return (
    <header className="sticky top-0 z-50 w-full border-b border-emerald-500/20 bg-gradient-to-r from-slate-950 via-blue-950 to-slate-950 shadow-2xl backdrop-blur-xl">
      <div className="container mx-auto flex h-52 items-center justify-between px-6">
        {/* Logo */}
        <div className="flex items-center gap-8">
          <div className="relative flex h-36 w-36 items-center justify-center">
            {!logoError ? (
              <Image
                src="/logo.png"
                alt="Logo"
                fill
                className="object-contain"
                priority
                onError={() => setLogoError(true)}
              />
            ) : (
              <Wallet className="h-20 w-20 text-emerald-400" strokeWidth={2.5} />
            )}
          </div>
          <div>
            <h1 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-cyan-400 to-blue-400 tracking-tight">GusFlow</h1>
          </div>
        </div>

        {/* Navigation */}
        <nav className="hidden md:flex items-center gap-5">
          {navigation.map((item) => {
            const Icon = item.icon
            const active = isActive(item.href)
            return (
              <button
                key={item.name}
                onClick={() => router.push(item.href)}
                className={`
                  flex items-center gap-5 px-10 py-6 rounded-2xl font-black text-2xl
                  transition-all duration-300 transform hover:scale-105
                  ${active
                    ? 'bg-gradient-to-r from-emerald-500 to-cyan-500 text-white shadow-lg shadow-emerald-500/30'
                    : 'text-slate-300 hover:bg-white/10 hover:text-white border border-slate-700/50 hover:border-emerald-500/50'
                  }
                `}
              >
                <Icon className="h-9 w-9" strokeWidth={2.5} />
                {item.name}
              </button>
            )
          })}
        </nav>

        {/* User section */}
        <div className="flex items-center gap-8">
          <div className="hidden sm:block text-right">
            <p className="text-2xl font-black text-white">{user.email}</p>
            <p className="text-lg text-emerald-400 font-bold">Administrador</p>
          </div>
          <Button
            variant="ghost"
            size="lg"
            onClick={handleLogout}
            className="h-20 px-10 text-red-400 hover:text-red-300 hover:bg-red-900/40 font-black text-2xl border-2 border-red-500/30 hover:border-red-500/60 rounded-xl"
          >
            <LogOut className="h-8 w-8 mr-3" strokeWidth={2.5} />
            Salir
          </Button>
        </div>
      </div>
    </header>
  )
}
