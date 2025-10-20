'use client'

export const dynamic = 'force-dynamic'

import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Home, AlertTriangle } from 'lucide-react'

export default function NotFound() {
  const router = useRouter()

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-950 via-blue-950 to-slate-900 p-8">
      <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-orange-500/30 shadow-2xl backdrop-blur-sm max-w-2xl w-full">
        <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-orange-500 to-red-500 opacity-5 rounded-full -mr-32 -mt-32"></div>
        <CardContent className="flex flex-col items-center justify-center py-28 px-8">
          <div className="p-10 rounded-3xl bg-gradient-to-br from-orange-500 via-red-500 to-pink-500 mb-10 shadow-2xl shadow-orange-500/30">
            <AlertTriangle className="h-28 w-28 text-white" strokeWidth={2.5} />
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
          <Button
            onClick={() => router.push('/dashboard')}
            className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-orange-600 via-red-600 to-pink-600 hover:from-orange-700 hover:via-red-700 hover:to-pink-700 text-white shadow-2xl shadow-orange-500/30"
          >
            <Home className="mr-4 h-9 w-9" strokeWidth={2.5} />
            Volver al inicio
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
