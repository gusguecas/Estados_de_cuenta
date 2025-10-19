'use client'

import { useAuth } from '@/lib/auth-context'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useEffect } from 'react'

export default function DashboardPage() {
  const { user, signOut, loading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!loading && !user) {
      router.push('/auth/login')
    }
  }, [user, loading, router])

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto"></div>
          <p className="mt-4 text-gray-600">Cargando...</p>
        </div>
      </div>
    )
  }

  if (!user) {
    return null
  }

  const handleSignOut = async () => {
    await signOut()
    router.push('/auth/login')
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
            <p className="text-gray-600 mt-1">Bienvenido, {user.email}</p>
          </div>
          <Button variant="outline" onClick={handleSignOut}>
            Cerrar Sesión
          </Button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <Card>
            <CardHeader>
              <CardTitle>🏢 Empresas</CardTitle>
              <CardDescription>Gestiona tus empresas</CardDescription>
            </CardHeader>
            <CardContent>
              <Button className="w-full" onClick={() => router.push('/empresas')}>
                Ver Empresas
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>👤 Personal</CardTitle>
              <CardDescription>Finanzas personales</CardDescription>
            </CardHeader>
            <CardContent>
              <Button className="w-full" onClick={() => router.push('/personal')}>
                Ver Personal
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>📊 Resumen</CardTitle>
              <CardDescription>Vista general</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">$0.00</p>
              <p className="text-sm text-gray-500">Saldo total</p>
            </CardContent>
          </Card>
        </div>

        <Card className="mt-8">
          <CardHeader>
            <CardTitle>🚀 Próximos pasos</CardTitle>
            <CardDescription>Completa la configuración de Firebase</CardDescription>
          </CardHeader>
          <CardContent className="prose max-w-none">
            <ol className="list-decimal list-inside space-y-2">
              <li>Configura Firebase siguiendo las instrucciones en <code>FIREBASE_SETUP.md</code></li>
              <li>Crea el archivo <code>.env.local</code> con tus credenciales</li>
              <li>Reinicia el servidor: <code>npm run dev</code></li>
              <li>¡Empieza a agregar empresas y cuentas!</li>
            </ol>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
