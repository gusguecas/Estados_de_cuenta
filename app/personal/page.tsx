'use client'

export const dynamic = 'force-dynamic'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import {
  getCuentas,
  deleteCuenta,
  getDocumentosFinancieros,
  deleteDocumentoFinanciero,
  getPersonas,
  deletePersona,
  getDocumentosPersonales,
  deleteDocumentoPersonal
} from '@/lib/firestore'
import type { CuentaBancaria, DocumentoFinanciero, Persona, DocumentoPersonal, TipoDocumentoPersonal } from '@/lib/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Plus, Edit, Trash2, CreditCard, Wallet, DollarSign, User, Calendar,
  FileText, Download, Eye, Users, Shield, AlertTriangle, Plane, Car,
  Heart, Home, GraduationCap, Hash, Building2, X, MapPin, ChevronDown
} from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { CuentaModal } from '@/components/cuenta-modal'
import { DocumentoFinancieroModal } from '@/components/documento-financiero-modal'
import { PersonaModal } from '@/components/persona-modal'
import { DocumentoPersonalModal } from '@/components/documento-personal-modal'
import { MainLayout } from '@/components/main-layout'
import Image from 'next/image'

export default function PersonalPage() {
  const { user, loading: authLoading } = useAuth()
  const router = useRouter()
  const [cuentas, setCuentas] = useState<CuentaBancaria[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [selectedCuenta, setSelectedCuenta] = useState<CuentaBancaria | null>(null)
  const [documentos, setDocumentos] = useState<DocumentoFinanciero[]>([])
  const [showDocumentoModal, setShowDocumentoModal] = useState(false)

  // Estados para personas y documentos personales
  const [personas, setPersonas] = useState<Persona[]>([])
  const [showPersonaModal, setShowPersonaModal] = useState(false)
  const [selectedPersona, setSelectedPersona] = useState<Persona | null>(null)
  const [documentosPersonales, setDocumentosPersonales] = useState<DocumentoPersonal[]>([])
  const [showDocumentoPersonalModal, setShowDocumentoPersonalModal] = useState(false)
  const [selectedDocumentoPersonal, setSelectedDocumentoPersonal] = useState<DocumentoPersonal | null>(null)
  const [showDetalleModal, setShowDetalleModal] = useState(false)
  const [documentoDetalle, setDocumentoDetalle] = useState<DocumentoPersonal | null>(null)
  const [filtroTipoDocumento, setFiltroTipoDocumento] = useState<TipoDocumentoPersonal | 'todos'>('todos')

  // Estados para secciones colapsables (por defecto colapsadas)
  const [seccionDocFinancierosAbierta, setSeccionDocFinancierosAbierta] = useState(false)
  const [seccionAlertasAbierta, setSeccionAlertasAbierta] = useState(false)
  const [seccionDocPersonalesAbierta, setSeccionDocPersonalesAbierta] = useState(false)
  const [seccionTablaAbierta, setSeccionTablaAbierta] = useState(false)

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/auth/login')
    }
  }, [user, authLoading, router])

  const loadCuentas = useCallback(async () => {
    if (!user) return

    try {
      setLoading(true)
      const data = await getCuentas(user.uid, 'personal')
      setCuentas(data)
    } catch (error) {
      console.error('Error al cargar cuentas:', error)
    } finally {
      setLoading(false)
    }
  }, [user])

  const loadDocumentos = useCallback(async () => {
    if (!user) return

    try {
      const data = await getDocumentosFinancieros(user.uid)
      setDocumentos(data)
    } catch (error) {
      console.error('Error al cargar documentos:', error)
    }
  }, [user])

  const loadPersonas = useCallback(async () => {
    if (!user) return

    try {
      const data = await getPersonas(user.uid)
      setPersonas(data)
    } catch (error) {
      console.error('Error al cargar personas:', error)
    }
  }, [user])

  const loadDocumentosPersonales = useCallback(async () => {
    if (!user) return

    try {
      const data = await getDocumentosPersonales(user.uid)
      setDocumentosPersonales(data)
    } catch (error) {
      console.error('Error al cargar documentos personales:', error)
    }
  }, [user])

  useEffect(() => {
    if (user) {
      loadCuentas()
      loadDocumentos()
      loadPersonas()
      loadDocumentosPersonales()
    }
  }, [user, loadCuentas, loadDocumentos, loadPersonas, loadDocumentosPersonales])

  const handleDeleteCuenta = async (id: string) => {
    if (!confirm('¿Estás seguro de eliminar esta cuenta?')) return

    try {
      await deleteCuenta(id)
      await loadCuentas()
    } catch (error) {
      console.error('Error al eliminar cuenta:', error)
    }
  }

  const handleDeleteDocumento = async (id: string) => {
    if (!confirm('¿Estás seguro de eliminar este documento?')) return

    try {
      await deleteDocumentoFinanciero(id)
      await loadDocumentos()
    } catch (error) {
      console.error('Error al eliminar documento:', error)
    }
  }

  const handleDeletePersona = async (id: string) => {
    // Verificar si tiene documentos asociados
    const docsPersona = documentosPersonales.filter(d => d.personaId === id)
    if (docsPersona.length > 0) {
      alert(`Esta persona tiene ${docsPersona.length} documento(s) asociado(s). Elimina primero los documentos.`)
      return
    }

    if (!confirm('¿Estás seguro de eliminar esta persona?')) return

    try {
      await deletePersona(id)
      await loadPersonas()
    } catch (error) {
      console.error('Error al eliminar persona:', error)
    }
  }

  const handleDeleteDocumentoPersonal = async (id: string) => {
    if (!confirm('¿Estás seguro de eliminar este documento?')) return

    try {
      await deleteDocumentoPersonal(id)
      await loadDocumentosPersonales()
    } catch (error) {
      console.error('Error al eliminar documento personal:', error)
    }
  }

  const getTipoDocumentoLabel = (tipo: string) => {
    const tipos: Record<string, string> = {
      buro_credito: 'Buró de Crédito',
      declaracion_anual: 'Declaración Anual',
      declaracion_mensual: 'Declaración Mensual',
      constancia_fiscal: 'Constancia Fiscal',
      otro: 'Otro'
    }
    return tipos[tipo] || tipo
  }

  const getTipoDocumentoBadge = (tipo: string) => {
    const variants: Record<string, string> = {
      buro_credito: 'bg-amber-500/20 text-amber-300 border-amber-500/50',
      declaracion_anual: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50',
      declaracion_mensual: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50',
      constancia_fiscal: 'bg-purple-500/20 text-purple-300 border-purple-500/50',
      otro: 'bg-slate-500/20 text-slate-300 border-slate-500/50'
    }
    return variants[tipo] || variants.otro
  }

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
    return (bytes / 1024 / 1024).toFixed(2) + ' MB'
  }

  const formatMoney = (amount: number, moneda: string) => {
    const formatter = new Intl.NumberFormat('es-MX', {
      style: 'currency',
      currency: moneda
    })
    return formatter.format(amount)
  }

  // Funciones para documentos personales
  const getTipoDocumentoPersonalLabel = (tipo: TipoDocumentoPersonal) => {
    const tipos: Record<TipoDocumentoPersonal, string> = {
      pasaporte: 'Pasaporte',
      visa: 'Visa',
      ine: 'INE',
      licencia_conducir: 'Licencia de Conducir',
      curp: 'CURP',
      acta_nacimiento: 'Acta de Nacimiento',
      acta_matrimonio: 'Acta de Matrimonio',
      rfc: 'RFC',
      comprobante_domicilio: 'Comprobante de Domicilio',
      poliza_seguro_auto: 'Seguro de Auto',
      poliza_seguro_vida: 'Seguro de Vida',
      poliza_gastos_medicos: 'Gastos Médicos',
      poliza_seguro_hogar: 'Seguro de Hogar',
      cartilla_militar: 'Cartilla Militar',
      cedula_profesional: 'Cédula Profesional',
      titulo_profesional: 'Título Profesional',
      seguro_social: 'Seguro Social',
      otro: 'Otro'
    }
    return tipos[tipo] || tipo
  }

  const getTipoDocumentoPersonalIcon = (tipo: TipoDocumentoPersonal) => {
    const iconos: Record<TipoDocumentoPersonal, typeof Plane> = {
      pasaporte: Plane,
      visa: Plane,
      ine: CreditCard,
      licencia_conducir: Car,
      curp: FileText,
      acta_nacimiento: FileText,
      acta_matrimonio: Heart,
      rfc: Building2,
      comprobante_domicilio: Home,
      poliza_seguro_auto: Car,
      poliza_seguro_vida: Shield,
      poliza_gastos_medicos: Heart,
      poliza_seguro_hogar: Home,
      cartilla_militar: Shield,
      cedula_profesional: GraduationCap,
      titulo_profesional: GraduationCap,
      seguro_social: Shield,
      otro: FileText
    }
    return iconos[tipo] || FileText
  }

  const getTipoDocumentoPersonalBadge = (tipo: TipoDocumentoPersonal) => {
    const variants: Record<string, string> = {
      pasaporte: 'bg-blue-500/20 text-blue-300 border-blue-500/50',
      visa: 'bg-indigo-500/20 text-indigo-300 border-indigo-500/50',
      ine: 'bg-green-500/20 text-green-300 border-green-500/50',
      licencia_conducir: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50',
      curp: 'bg-purple-500/20 text-purple-300 border-purple-500/50',
      acta_nacimiento: 'bg-pink-500/20 text-pink-300 border-pink-500/50',
      acta_matrimonio: 'bg-rose-500/20 text-rose-300 border-rose-500/50',
      rfc: 'bg-orange-500/20 text-orange-300 border-orange-500/50',
      comprobante_domicilio: 'bg-slate-500/20 text-slate-300 border-slate-500/50',
      poliza_seguro_auto: 'bg-teal-500/20 text-teal-300 border-teal-500/50',
      poliza_seguro_vida: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50',
      poliza_gastos_medicos: 'bg-red-500/20 text-red-300 border-red-500/50',
      poliza_seguro_hogar: 'bg-amber-500/20 text-amber-300 border-amber-500/50',
      cartilla_militar: 'bg-stone-500/20 text-stone-300 border-stone-500/50',
      cedula_profesional: 'bg-violet-500/20 text-violet-300 border-violet-500/50',
      titulo_profesional: 'bg-fuchsia-500/20 text-fuchsia-300 border-fuchsia-500/50',
      seguro_social: 'bg-lime-500/20 text-lime-300 border-lime-500/50',
      otro: 'bg-gray-500/20 text-gray-300 border-gray-500/50'
    }
    return variants[tipo] || variants.otro
  }

  const getParentescoLabel = (parentesco: string) => {
    const labels: Record<string, string> = {
      titular: 'Titular (Yo)',
      esposa: 'Esposa',
      esposo: 'Esposo',
      hijo: 'Hijo',
      hija: 'Hija',
      padre: 'Padre',
      madre: 'Madre',
      otro: 'Otro'
    }
    return labels[parentesco] || parentesco
  }

  const formatDate = (date: Date) => {
    return new Intl.DateTimeFormat('es-MX', {
      day: '2-digit',
      month: 'short',
      year: 'numeric'
    }).format(date)
  }

  // Calcular documentos próximos a vencer (6 meses = 180 días de anticipación)
  const documentosProximosAVencer = documentosPersonales.filter(doc => {
    if (!doc.fechaVencimiento) return false
    const hoy = new Date()
    const vencimiento = new Date(doc.fechaVencimiento)
    const diasHastaVencimiento = Math.ceil((vencimiento.getTime() - hoy.getTime()) / (1000 * 60 * 60 * 24))
    return diasHastaVencimiento >= -30 && diasHastaVencimiento <= 180 // 6 meses antes, incluye vencidos hasta 30 días
  }).sort((a, b) => {
    const fechaA = a.fechaVencimiento ? new Date(a.fechaVencimiento).getTime() : 0
    const fechaB = b.fechaVencimiento ? new Date(b.fechaVencimiento).getTime() : 0
    return fechaA - fechaB
  })

  const getDiasHastaVencimiento = (fecha: Date) => {
    const hoy = new Date()
    hoy.setHours(0, 0, 0, 0)
    const vencimiento = new Date(fecha)
    vencimiento.setHours(0, 0, 0, 0)
    return Math.ceil((vencimiento.getTime() - hoy.getTime()) / (1000 * 60 * 60 * 24))
  }

  const getVencimientoBadge = (dias: number) => {
    if (dias < 0) return 'bg-red-600/30 text-red-300 border-red-500'
    if (dias === 0) return 'bg-red-500/30 text-red-300 border-red-500'
    if (dias <= 7) return 'bg-red-500/20 text-red-300 border-red-500/50'
    if (dias <= 30) return 'bg-orange-500/20 text-orange-300 border-orange-500/50'
    if (dias <= 60) return 'bg-amber-500/20 text-amber-300 border-amber-500/50'
    if (dias <= 90) return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/50'
    if (dias <= 120) return 'bg-lime-500/20 text-lime-300 border-lime-500/50'
    return 'bg-green-500/20 text-green-300 border-green-500/50'
  }

  const getVencimientoText = (dias: number) => {
    if (dias < 0) return `Vencido hace ${Math.abs(dias)} días`
    if (dias === 0) return 'Vence hoy'
    if (dias === 1) return 'Vence mañana'
    return `Vence en ${dias} días`
  }

  const getTipoCuentaBadge = (tipo: string) => {
    const variants: Record<string, { label: string; className: string }> = {
      cheques: { label: 'Cheques', className: 'bg-blue-500/20 text-blue-300 border-blue-500/50 text-lg font-bold px-4 py-2' },
      credito: { label: 'Crédito', className: 'bg-purple-500/20 text-purple-300 border-purple-500/50 text-lg font-bold px-4 py-2' },
      prestamo: { label: 'Préstamo', className: 'bg-orange-500/20 text-orange-300 border-orange-500/50 text-lg font-bold px-4 py-2' },
      ahorro: { label: 'Ahorro', className: 'bg-green-500/20 text-green-300 border-green-500/50 text-lg font-bold px-4 py-2' }
    }
    const config = variants[tipo] || variants.cheques
    return <Badge className={config.className}>{config.label}</Badge>
  }

  if (authLoading || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-950 via-blue-950 to-slate-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-24 w-24 border-4 border-emerald-500 border-t-transparent mx-auto"></div>
          <p className="mt-8 text-3xl font-black text-white">Cargando finanzas personales...</p>
        </div>
      </div>
    )
  }

  if (!user) {
    return null
  }

  // Agrupar cuentas por moneda
  const saldosPorMoneda = cuentas.reduce((acc, cuenta) => {
    const moneda = cuenta.moneda
    if (!acc[moneda]) {
      acc[moneda] = { total: 0, cuentas: 0 }
    }
    acc[moneda].total += cuenta.saldoActual || 0
    acc[moneda].cuentas += 1
    return acc
  }, {} as Record<string, { total: number; cuentas: number }>)

  // Calcular pagos por tarjeta de crédito
  const hoy = new Date()
  const diaActual = hoy.getDate()
  const mesActual = hoy.getMonth()
  const añoActual = hoy.getFullYear()

  const pagosPorTarjeta = cuentas
    .filter(c => c.tipoCuenta === 'credito' && c.diaLimitePago)
    .map(cuenta => {
      const diaLimite = cuenta.diaLimitePago!
      let fechaLimite = new Date(añoActual, mesActual, diaLimite)

      if (diaLimite < diaActual) {
        fechaLimite = new Date(añoActual, mesActual + 1, diaLimite)
      }

      const diasHasta = Math.ceil((fechaLimite.getTime() - hoy.getTime()) / (1000 * 60 * 60 * 24))

      return {
        fecha: diasHasta === 0 ? 'Hoy' : diasHasta === 1 ? 'Mañana' : `${diasHasta} días`,
        cuenta: cuenta.nombre,
        diasNumerico: diasHasta,
        monto: cuenta.limiteCredito ? cuenta.limiteCredito - cuenta.saldoActual : Math.abs(cuenta.saldoActual),
        moneda: cuenta.moneda
      }
    })
    .sort((a, b) => a.diasNumerico - b.diasNumerico)

  return (
    <MainLayout>
      <div className="space-y-10">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-fuchsia-400 flex items-center gap-5">
              <div className="p-5 rounded-2xl bg-gradient-to-br from-purple-500 via-pink-500 to-fuchsia-500 shadow-2xl shadow-purple-500/30">
                <User className="h-14 w-14 text-white" strokeWidth={2.5} />
              </div>
              Finanzas Personales
            </h1>
            <p className="text-2xl text-purple-300 mt-3 font-semibold">
              Gestiona y administra tus cuentas personales
            </p>
          </div>
          <Button
            onClick={() => setShowModal(true)}
            className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-purple-600 via-pink-600 to-fuchsia-600 hover:from-purple-700 hover:via-pink-700 hover:to-fuchsia-700 text-white shadow-2xl shadow-purple-500/30 hover:shadow-purple-500/50 transition-all"
          >
            <Plus className="mr-4 h-9 w-9" strokeWidth={2.5} />
            Nueva Cuenta
          </Button>
        </div>

        {/* KPIs Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {/* Total Cuentas */}
          <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-purple-500/30 shadow-2xl backdrop-blur-sm lg:col-span-1">
            <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-purple-500 to-pink-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
            <CardContent className="p-8">
              <div className="bg-purple-500/10 border-2 border-purple-500/30 rounded-xl p-5">
                <div className="flex items-center gap-4 mb-3">
                  <Wallet className="h-9 w-9 text-purple-400" strokeWidth={2.5} />
                  <span className="text-2xl text-purple-300 font-bold">Total Cuentas</span>
                </div>
                <p className="text-5xl font-black text-white ml-12">{cuentas.length}</p>
              </div>
            </CardContent>
          </Card>

          {/* Saldos por Moneda */}
          {Object.entries(saldosPorMoneda).slice(0, 1).map(([moneda, datos]) => {
            const monedaSymbol = moneda === 'MXN' ? '🇲🇽' : moneda === 'USD' ? '🇺🇸' : '🇪🇺'
            return (
              <Card key={moneda} className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-cyan-500/30 shadow-2xl backdrop-blur-sm lg:col-span-1">
                <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-cyan-500 to-blue-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
                <CardContent className="p-8">
                  <div className="bg-cyan-500/10 border-2 border-cyan-500/30 rounded-xl p-5">
                    <div className="flex items-center gap-4 mb-4">
                      <DollarSign className="h-9 w-9 text-cyan-400" strokeWidth={2.5} />
                      <span className="text-2xl text-cyan-300 font-bold">Saldo {monedaSymbol}</span>
                    </div>
                    <div className="ml-12">
                      <span className="text-4xl font-black text-white">
                        {new Intl.NumberFormat('es-MX', {
                          style: 'currency',
                          currency: moneda,
                          minimumFractionDigits: 2
                        }).format(datos.total)}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )
          })}

          {/* Pagos de Tarjetas de Crédito */}
          {pagosPorTarjeta.length > 0 && (
            <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-emerald-500/30 shadow-2xl backdrop-blur-sm lg:col-span-2">
              <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-emerald-500 to-green-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
              <CardContent className="p-8">
                <div className="bg-emerald-500/10 border-2 border-emerald-500/30 rounded-xl p-5">
                  <div className="flex items-center gap-4 mb-4">
                    <Calendar className="h-7 w-7 text-emerald-400" strokeWidth={2.5} />
                    <span className="text-xl text-emerald-300 font-bold">Próximos Pagos</span>
                  </div>
                  <div className="ml-12 space-y-3">
                    {pagosPorTarjeta.map((pago, index) => (
                      <div key={index} className="border-b border-emerald-500/20 last:border-0 pb-3 last:pb-0">
                        <div className="flex items-center justify-between gap-4">
                          <p className="text-lg text-white font-black flex-1">{pago.cuenta}</p>
                          <p className="text-xl font-black text-emerald-300">{pago.fecha}</p>
                          <p className="text-lg text-emerald-300 font-black text-right">
                            {formatMoney(pago.monto, pago.moneda)}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Cuentas Section */}
        {cuentas.length === 0 ? (
          <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-purple-500/30 shadow-2xl backdrop-blur-sm">
            <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-purple-500 to-pink-500 opacity-5 rounded-full -mr-32 -mt-32"></div>
            <CardContent className="flex flex-col items-center justify-center py-28">
              <div className="p-10 rounded-3xl bg-gradient-to-br from-purple-500 via-pink-500 to-fuchsia-500 mb-10 shadow-2xl shadow-purple-500/30">
                <Wallet className="h-28 w-28 text-white" strokeWidth={2.5} />
              </div>
              <h3 className="text-5xl font-black text-white mb-5">
                No hay cuentas personales registradas
              </h3>
              <p className="text-2xl text-purple-300 mb-12 font-semibold">
                Comienza creando tu primera cuenta personal
              </p>
              <Button
                onClick={() => setShowModal(true)}
                className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-purple-600 via-pink-600 to-fuchsia-600 hover:from-purple-700 hover:via-pink-700 hover:to-fuchsia-700 text-white shadow-2xl shadow-purple-500/30"
              >
                <Plus className="mr-4 h-9 w-9" strokeWidth={2.5} />
                Crear Primera Cuenta
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-10">
            {/* Cuentas de Cheques y Ahorro */}
            {cuentas.filter(c => c.tipoCuenta === 'cheques' || c.tipoCuenta === 'ahorro').length > 0 && (
              <div>
                <h2 className="text-4xl font-black text-white mb-6 flex items-center gap-3">
                  <Wallet className="h-10 w-10 text-blue-400" strokeWidth={2.5} />
                  Cuentas de Cheques y Ahorro
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                  {cuentas.filter(c => c.tipoCuenta === 'cheques' || c.tipoCuenta === 'ahorro').map((cuenta) => (
                    <Card
                      key={cuenta.id}
                      className="group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-cyan-500/30 shadow-2xl hover:shadow-cyan-500/20 transition-all duration-300 cursor-pointer hover:-translate-y-2 hover:border-cyan-500/50 backdrop-blur-sm"
                      onClick={() => router.push(`/cuentas/${cuenta.id}`)}
                    >
                      <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-cyan-500 to-blue-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
                      <CardHeader className="pb-6">
                        <div className="flex flex-col items-center gap-4 mb-4">
                          <div className="relative w-32 h-32 flex items-center justify-center">
                            {cuenta.logo ? (
                              <Image
                                src={cuenta.logo}
                                alt={cuenta.banco}
                                fill
                                className="object-contain scale-[2.24]"
                              />
                            ) : (
                              <div className="p-3 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-500 shadow-2xl shadow-cyan-500/30">
                                <CreditCard className="h-16 w-16 text-white" strokeWidth={2.5} />
                              </div>
                            )}
                          </div>
                          <div className="flex items-center gap-3">
                            <span className="text-5xl">
                              {cuenta.moneda === 'MXN' ? '🇲🇽' : cuenta.moneda === 'USD' ? '🇺🇸' : '🇪🇺'}
                            </span>
                            {getTipoCuentaBadge(cuenta.tipoCuenta)}
                          </div>
                        </div>
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1 text-center">
                            <CardTitle className="text-3xl font-black text-white mb-3">
                              {cuenta.nombre}
                            </CardTitle>
                            <CardDescription className="text-xl text-cyan-300 font-semibold">
                              {cuenta.banco} • {cuenta.numeroCuenta}
                            </CardDescription>
                          </div>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-6">
                          <div>
                            <p className="text-xl font-bold text-cyan-300 uppercase tracking-wide mb-2">Saldo Actual</p>
                            <p className="text-5xl font-black text-emerald-400">
                              {formatMoney(cuenta.saldoActual, cuenta.moneda)}
                            </p>
                          </div>
                          <div className="flex gap-3 pt-4">
                            <Button
                              variant="outline"
                              size="lg"
                              className="flex-1 h-14 text-lg font-bold bg-blue-500/10 border-2 border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400 hover:text-white"
                              onClick={(e) => {
                                e.stopPropagation()
                                setSelectedCuenta(cuenta)
                                setShowModal(true)
                              }}
                            >
                              <Edit className="h-6 w-6 mr-2" strokeWidth={2.5} />
                              Editar
                            </Button>
                            <Button
                              variant="outline"
                              size="lg"
                              className="h-14 px-6 text-lg font-bold bg-red-500/10 border-2 border-red-500/50 text-red-300 hover:bg-red-500/20 hover:border-red-400 hover:text-white"
                              onClick={(e) => {
                                e.stopPropagation()
                                handleDeleteCuenta(cuenta.id)
                              }}
                            >
                              <Trash2 className="h-6 w-6" strokeWidth={2.5} />
                            </Button>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </div>
            )}

            {/* Tarjetas de Crédito */}
            {cuentas.filter(c => c.tipoCuenta === 'credito').length > 0 && (
              <div>
                <h2 className="text-4xl font-black text-white mb-6 flex items-center gap-3">
                  <CreditCard className="h-10 w-10 text-purple-400" strokeWidth={2.5} />
                  Tarjetas de Crédito
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                  {cuentas.filter(c => c.tipoCuenta === 'credito').map((cuenta) => (
              <Card
                key={cuenta.id}
                className="group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-cyan-500/30 shadow-2xl hover:shadow-cyan-500/20 transition-all duration-300 cursor-pointer hover:-translate-y-2 hover:border-cyan-500/50 backdrop-blur-sm"
                onClick={() => router.push(`/cuentas/${cuenta.id}`)}
              >
                <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-cyan-500 to-blue-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
                <CardHeader className="pb-6 pt-8">
                  <div className="flex flex-col items-center gap-4 mb-4">
                    <div className="relative w-28 h-28 flex items-center justify-center">
                      {cuenta.logo ? (
                        <Image
                          src={cuenta.logo}
                          alt={cuenta.banco}
                          fill
                          className="object-contain scale-[2.0]"
                        />
                      ) : (
                        <div className="p-3 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-500 shadow-2xl shadow-cyan-500/30">
                          <CreditCard className="h-14 w-14 text-white" strokeWidth={2.5} />
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-5xl">
                        {cuenta.moneda === 'MXN' ? '🇲🇽' : cuenta.moneda === 'USD' ? '🇺🇸' : '🇪🇺'}
                      </span>
                      {getTipoCuentaBadge(cuenta.tipoCuenta)}
                    </div>
                  </div>
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 text-center">
                      <CardTitle className="text-3xl font-black text-white mb-3">
                        {cuenta.nombre}
                      </CardTitle>
                      <CardDescription className="text-xl text-cyan-300 font-semibold">
                        {cuenta.banco} • {cuenta.numeroCuenta}
                      </CardDescription>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="pb-8">
                  <div className="space-y-6">
                    <div>
                      <p className="text-xl font-bold text-cyan-300 uppercase tracking-wide mb-2">Saldo Actual</p>
                      <p className="text-5xl font-black text-emerald-400">
                        {formatMoney(cuenta.saldoActual, cuenta.moneda)}
                      </p>
                    </div>
                    {cuenta.limiteCredito && cuenta.tipoCuenta === 'credito' && (
                      <div className="flex justify-between text-lg pt-3 border-t border-cyan-500/20">
                        <span className="text-cyan-300 font-bold">Límite de Crédito:</span>
                        <span className="font-black text-white">
                          {formatMoney(cuenta.limiteCredito, cuenta.moneda)}
                        </span>
                      </div>
                    )}
                    <div className="flex gap-3 pt-4">
                      <Button
                        variant="outline"
                        size="lg"
                        className="flex-1 h-14 text-lg font-bold bg-blue-500/10 border-2 border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400 hover:text-white"
                        onClick={(e) => {
                          e.stopPropagation()
                          setSelectedCuenta(cuenta)
                          setShowModal(true)
                        }}
                      >
                        <Edit className="h-6 w-6 mr-2" strokeWidth={2.5} />
                        Editar
                      </Button>
                      <Button
                        variant="outline"
                        size="lg"
                        className="h-14 px-6 text-lg font-bold bg-red-500/10 border-2 border-red-500/50 text-red-300 hover:bg-red-500/20 hover:border-red-400 hover:text-white"
                        onClick={(e) => {
                          e.stopPropagation()
                          handleDeleteCuenta(cuenta.id)
                        }}
                      >
                        <Trash2 className="h-6 w-6" strokeWidth={2.5} />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Documentos Financieros */}
        <div>
          <div
            className="flex items-center justify-between mb-6 cursor-pointer group"
            onClick={() => setSeccionDocFinancierosAbierta(!seccionDocFinancierosAbierta)}
          >
            <h2 className="text-4xl font-black text-white flex items-center gap-3">
              <FileText className="h-10 w-10 text-amber-400" strokeWidth={2.5} />
              Documentos Financieros
              <ChevronDown
                className={`h-8 w-8 text-amber-400 transition-transform duration-300 ${seccionDocFinancierosAbierta ? 'rotate-180' : ''}`}
                strokeWidth={2.5}
              />
              <span className="text-lg font-semibold text-amber-300/70">
                ({documentos.length})
              </span>
            </h2>
            <Button
              onClick={(e) => {
                e.stopPropagation()
                setShowDocumentoModal(true)
              }}
              className="h-16 px-8 text-xl font-black bg-gradient-to-r from-amber-600 via-orange-600 to-red-600 hover:from-amber-700 hover:via-orange-700 hover:to-red-700 text-white shadow-2xl shadow-amber-500/30 hover:shadow-amber-500/50 transition-all"
            >
              <Plus className="mr-3 h-7 w-7" strokeWidth={2.5} />
              Subir Documento
            </Button>
          </div>

          {seccionDocFinancierosAbierta && (documentos.length === 0 ? (
            <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-amber-500/30 shadow-2xl backdrop-blur-sm">
              <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-amber-500 to-orange-500 opacity-5 rounded-full -mr-32 -mt-32"></div>
              <CardContent className="flex flex-col items-center justify-center py-20">
                <div className="p-8 rounded-3xl bg-gradient-to-br from-amber-500 via-orange-500 to-red-500 mb-8 shadow-2xl shadow-amber-500/30">
                  <FileText className="h-20 w-20 text-white" strokeWidth={2.5} />
                </div>
                <h3 className="text-4xl font-black text-white mb-4">
                  No hay documentos financieros
                </h3>
                <p className="text-xl text-amber-300 mb-10 font-semibold">
                  Sube tu buró de crédito, declaraciones fiscales y más
                </p>
                <Button
                  onClick={() => setShowDocumentoModal(true)}
                  className="h-16 px-10 text-xl font-black bg-gradient-to-r from-amber-600 via-orange-600 to-red-600 hover:from-amber-700 hover:via-orange-700 hover:to-red-700 text-white shadow-2xl shadow-amber-500/30"
                >
                  <Plus className="mr-3 h-7 w-7" strokeWidth={2.5} />
                  Subir Primer Documento
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {documentos.map((documento) => (
                <Card
                  key={documento.id}
                  className="group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-amber-500/30 shadow-2xl hover:shadow-amber-500/20 transition-all duration-300 hover:-translate-y-2 hover:border-amber-500/50 backdrop-blur-sm"
                >
                  <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-amber-500 to-orange-500 opacity-10 rounded-full -mr-20 -mt-20"></div>
                  <CardHeader className="pb-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="p-3 rounded-xl bg-gradient-to-br from-amber-500 via-orange-500 to-red-500 shadow-lg shadow-amber-500/30">
                        <FileText className="h-8 w-8 text-white" strokeWidth={2.5} />
                      </div>
                      <Badge className={`${getTipoDocumentoBadge(documento.tipoDocumento)} text-sm font-bold px-3 py-1`}>
                        {getTipoDocumentoLabel(documento.tipoDocumento)}
                      </Badge>
                    </div>
                    <CardTitle className="text-2xl font-black text-white mt-4">
                      {documento.nombre}
                    </CardTitle>
                    {documento.descripcion && (
                      <CardDescription className="text-base text-amber-300 font-semibold">
                        {documento.descripcion}
                      </CardDescription>
                    )}
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex flex-wrap gap-2 text-sm">
                        {documento.año && (
                          <span className="px-3 py-1 bg-slate-800/50 rounded-lg text-slate-300 font-semibold">
                            Año: {documento.año}
                          </span>
                        )}
                        {documento.mes && (
                          <span className="px-3 py-1 bg-slate-800/50 rounded-lg text-slate-300 font-semibold">
                            Mes: {documento.mes}
                          </span>
                        )}
                      </div>
                      <div className="text-sm text-slate-400">
                        <p className="font-semibold truncate" title={documento.nombreArchivo}>
                          {documento.nombreArchivo}
                        </p>
                        <p>{formatFileSize(documento.tamanioArchivo)}</p>
                      </div>
                      <div className="flex gap-2 pt-3">
                        <Button
                          variant="outline"
                          size="sm"
                          className="flex-1 h-12 text-base font-bold bg-amber-500/10 border-2 border-amber-500/50 text-amber-300 hover:bg-amber-500/20 hover:border-amber-400 hover:text-white"
                          onClick={() => window.open(documento.archivoUrl, '_blank')}
                        >
                          <Eye className="h-5 w-5 mr-2" strokeWidth={2.5} />
                          Ver
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="flex-1 h-12 text-base font-bold bg-emerald-500/10 border-2 border-emerald-500/50 text-emerald-300 hover:bg-emerald-500/20 hover:border-emerald-400 hover:text-white"
                          onClick={() => {
                            const link = document.createElement('a')
                            link.href = documento.archivoUrl
                            link.download = documento.nombreArchivo
                            link.click()
                          }}
                        >
                          <Download className="h-5 w-5 mr-2" strokeWidth={2.5} />
                          Descargar
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-12 px-4 text-base font-bold bg-red-500/10 border-2 border-red-500/50 text-red-300 hover:bg-red-500/20 hover:border-red-400 hover:text-white"
                          onClick={() => handleDeleteDocumento(documento.id)}
                        >
                          <Trash2 className="h-5 w-5" strokeWidth={2.5} />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ))}
        </div>

        {/* ================================================================== */}
        {/* SECCIÓN DE DOCUMENTOS PERSONALES */}
        {/* ================================================================== */}

        {/* Alertas de Vencimiento */}
        {documentosProximosAVencer.length > 0 && (
          <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-red-950/30 border-red-500/40 shadow-2xl backdrop-blur-sm">
            <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-red-500 to-orange-500 opacity-10 rounded-full -mr-32 -mt-32"></div>
            <CardHeader className="pb-4">
              <div className="flex items-center gap-4">
                <div className="p-4 rounded-2xl bg-gradient-to-br from-red-500 via-orange-500 to-amber-500 shadow-xl shadow-red-500/30">
                  <AlertTriangle className="h-10 w-10 text-white" strokeWidth={2.5} />
                </div>
                <div>
                  <CardTitle className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-orange-400">
                    Documentos Próximos a Vencer
                  </CardTitle>
                  <CardDescription className="text-lg text-red-300 font-semibold mt-1">
                    {documentosProximosAVencer.length} documento(s) vence(n) en los próximos 6 meses
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {documentosProximosAVencer.map((doc) => {
                  const persona = personas.find(p => p.id === doc.personaId)
                  const dias = getDiasHastaVencimiento(doc.fechaVencimiento!)
                  const IconComponent = getTipoDocumentoPersonalIcon(doc.tipoDocumento)
                  return (
                    <div
                      key={doc.id}
                      className={`p-4 rounded-xl border-2 ${getVencimientoBadge(dias)} flex items-center gap-4`}
                    >
                      <div className="p-3 rounded-xl bg-slate-800/50">
                        <IconComponent className="h-8 w-8 text-white" strokeWidth={2} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-lg font-black text-white truncate">{doc.nombre}</p>
                        <p className="text-sm text-slate-300 font-semibold">
                          {persona ? `${persona.nombre} ${persona.apellidos}` : 'Sin asignar'}
                        </p>
                        <p className="text-base font-black mt-1">{getVencimientoText(dias)}</p>
                      </div>
                    </div>
                  )
                })}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Personas / Familiares */}
        <div>
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-4xl font-black text-white flex items-center gap-3">
              <Users className="h-10 w-10 text-pink-400" strokeWidth={2.5} />
              Personas / Familiares
            </h2>
            <Button
              onClick={() => {
                setSelectedPersona(null)
                setShowPersonaModal(true)
              }}
              className="h-16 px-8 text-xl font-black bg-gradient-to-r from-pink-600 via-rose-600 to-red-600 hover:from-pink-700 hover:via-rose-700 hover:to-red-700 text-white shadow-2xl shadow-pink-500/30 hover:shadow-pink-500/50 transition-all"
            >
              <Plus className="mr-3 h-7 w-7" strokeWidth={2.5} />
              Agregar Persona
            </Button>
          </div>

          {personas.length === 0 ? (
            <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-pink-500/30 shadow-2xl backdrop-blur-sm">
              <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-pink-500 to-rose-500 opacity-5 rounded-full -mr-32 -mt-32"></div>
              <CardContent className="flex flex-col items-center justify-center py-16">
                <div className="p-8 rounded-3xl bg-gradient-to-br from-pink-500 via-rose-500 to-red-500 mb-8 shadow-2xl shadow-pink-500/30">
                  <Users className="h-20 w-20 text-white" strokeWidth={2.5} />
                </div>
                <h3 className="text-4xl font-black text-white mb-4">
                  No hay personas registradas
                </h3>
                <p className="text-xl text-pink-300 mb-10 font-semibold text-center">
                  Agrega a ti mismo y a tus familiares para poder registrar sus documentos
                </p>
                <Button
                  onClick={() => {
                    setSelectedPersona(null)
                    setShowPersonaModal(true)
                  }}
                  className="h-16 px-10 text-xl font-black bg-gradient-to-r from-pink-600 via-rose-600 to-red-600 hover:from-pink-700 hover:via-rose-700 hover:to-red-700 text-white shadow-2xl shadow-pink-500/30"
                >
                  <Plus className="mr-3 h-7 w-7" strokeWidth={2.5} />
                  Agregar Primera Persona
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {personas.map((persona) => {
                const docsCount = documentosPersonales.filter(d => d.personaId === persona.id).length
                return (
                  <Card
                    key={persona.id}
                    className="group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-pink-500/30 shadow-2xl hover:shadow-pink-500/20 transition-all duration-300 hover:-translate-y-2 hover:border-pink-500/50 backdrop-blur-sm"
                  >
                    <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-pink-500 to-rose-500 opacity-10 rounded-full -mr-20 -mt-20"></div>
                    <CardHeader className="pb-4">
                      <div className="flex items-center justify-between gap-3">
                        <div className="p-3 rounded-xl bg-gradient-to-br from-pink-500 via-rose-500 to-red-500 shadow-lg shadow-pink-500/30">
                          <User className="h-8 w-8 text-white" strokeWidth={2.5} />
                        </div>
                        <Badge className="bg-pink-500/20 text-pink-300 border-pink-500/50 text-sm font-bold px-3 py-1">
                          {getParentescoLabel(persona.parentesco)}
                        </Badge>
                      </div>
                      <CardTitle className="text-2xl font-black text-white mt-4">
                        {persona.nombre} {persona.apellidos}
                      </CardTitle>
                      {persona.fechaNacimiento && (
                        <CardDescription className="text-base text-pink-300 font-semibold flex items-center gap-2">
                          <Calendar className="h-4 w-4" />
                          {formatDate(persona.fechaNacimiento)}
                        </CardDescription>
                      )}
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-4">
                        <div className="flex items-center gap-2 text-slate-300">
                          <FileText className="h-5 w-5 text-teal-400" />
                          <span className="font-semibold">{docsCount} documento(s) registrado(s)</span>
                        </div>
                        <div className="flex gap-2 pt-3">
                          <Button
                            variant="outline"
                            size="sm"
                            className="flex-1 h-12 text-base font-bold bg-pink-500/10 border-2 border-pink-500/50 text-pink-300 hover:bg-pink-500/20 hover:border-pink-400 hover:text-white"
                            onClick={() => {
                              setSelectedPersona(persona)
                              setShowPersonaModal(true)
                            }}
                          >
                            <Edit className="h-5 w-5 mr-2" strokeWidth={2.5} />
                            Editar
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-12 px-4 text-base font-bold bg-red-500/10 border-2 border-red-500/50 text-red-300 hover:bg-red-500/20 hover:border-red-400 hover:text-white"
                            onClick={() => handleDeletePersona(persona.id)}
                          >
                            <Trash2 className="h-5 w-5" strokeWidth={2.5} />
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          )}
        </div>

        {/* Documentos Personales */}
        <div>
          <div
            className="flex items-center justify-between mb-6 cursor-pointer group"
            onClick={() => setSeccionDocPersonalesAbierta(!seccionDocPersonalesAbierta)}
          >
            <h2 className="text-4xl font-black text-white flex items-center gap-3">
              <Shield className="h-10 w-10 text-teal-400" strokeWidth={2.5} />
              Documentos Personales
              <ChevronDown
                className={`h-8 w-8 text-teal-400 transition-transform duration-300 ${seccionDocPersonalesAbierta ? 'rotate-180' : ''}`}
                strokeWidth={2.5}
              />
              <span className="text-lg font-semibold text-teal-300/70">
                ({documentosPersonales.length})
              </span>
            </h2>
            <Button
              onClick={(e) => {
                e.stopPropagation()
                setSelectedDocumentoPersonal(null)
                setShowDocumentoPersonalModal(true)
              }}
              disabled={personas.length === 0}
              className="h-16 px-8 text-xl font-black bg-gradient-to-r from-teal-600 via-cyan-600 to-blue-600 hover:from-teal-700 hover:via-cyan-700 hover:to-blue-700 text-white shadow-2xl shadow-teal-500/30 hover:shadow-teal-500/50 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Plus className="mr-3 h-7 w-7" strokeWidth={2.5} />
              Agregar Documento
            </Button>
          </div>

          {seccionDocPersonalesAbierta && (personas.length === 0 ? (
            <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-teal-500/30 shadow-2xl backdrop-blur-sm">
              <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-teal-500 to-cyan-500 opacity-5 rounded-full -mr-32 -mt-32"></div>
              <CardContent className="flex flex-col items-center justify-center py-16">
                <div className="p-8 rounded-3xl bg-gradient-to-br from-teal-500 via-cyan-500 to-blue-500 mb-8 shadow-2xl shadow-teal-500/30">
                  <Shield className="h-20 w-20 text-white" strokeWidth={2.5} />
                </div>
                <h3 className="text-4xl font-black text-white mb-4">
                  Primero agrega personas
                </h3>
                <p className="text-xl text-teal-300 mb-10 font-semibold text-center">
                  Para registrar documentos personales, primero debes agregar a las personas
                </p>
              </CardContent>
            </Card>
          ) : documentosPersonales.length === 0 ? (
            <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-teal-500/30 shadow-2xl backdrop-blur-sm">
              <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-teal-500 to-cyan-500 opacity-5 rounded-full -mr-32 -mt-32"></div>
              <CardContent className="flex flex-col items-center justify-center py-16">
                <div className="p-8 rounded-3xl bg-gradient-to-br from-teal-500 via-cyan-500 to-blue-500 mb-8 shadow-2xl shadow-teal-500/30">
                  <Shield className="h-20 w-20 text-white" strokeWidth={2.5} />
                </div>
                <h3 className="text-4xl font-black text-white mb-4">
                  No hay documentos personales
                </h3>
                <p className="text-xl text-teal-300 mb-10 font-semibold text-center">
                  Registra pasaportes, visas, INE, licencias, pólizas de seguros y más
                </p>
                <Button
                  onClick={() => {
                    setSelectedDocumentoPersonal(null)
                    setShowDocumentoPersonalModal(true)
                  }}
                  className="h-16 px-10 text-xl font-black bg-gradient-to-r from-teal-600 via-cyan-600 to-blue-600 hover:from-teal-700 hover:via-cyan-700 hover:to-blue-700 text-white shadow-2xl shadow-teal-500/30"
                >
                  <Plus className="mr-3 h-7 w-7" strokeWidth={2.5} />
                  Agregar Primer Documento
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {documentosPersonales.map((doc) => {
                const persona = personas.find(p => p.id === doc.personaId)
                const IconComponent = getTipoDocumentoPersonalIcon(doc.tipoDocumento)
                const tieneVencimiento = doc.fechaVencimiento
                const diasVencimiento = tieneVencimiento ? getDiasHastaVencimiento(doc.fechaVencimiento!) : null

                return (
                  <Card
                    key={doc.id}
                    className={`group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 shadow-2xl hover:shadow-teal-500/20 transition-all duration-300 hover:-translate-y-2 backdrop-blur-sm cursor-pointer ${
                      diasVencimiento !== null && diasVencimiento <= 30
                        ? 'border-red-500/50 hover:border-red-500'
                        : 'border-teal-500/30 hover:border-teal-500/50'
                    }`}
                    onClick={() => {
                      setDocumentoDetalle(doc)
                      setShowDetalleModal(true)
                    }}
                  >
                    <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-teal-500 to-cyan-500 opacity-10 rounded-full -mr-20 -mt-20"></div>
                    <CardHeader className="pb-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="p-3 rounded-xl bg-gradient-to-br from-teal-500 via-cyan-500 to-blue-500 shadow-lg shadow-teal-500/30">
                          <IconComponent className="h-8 w-8 text-white" strokeWidth={2.5} />
                        </div>
                        <Badge className={`${getTipoDocumentoPersonalBadge(doc.tipoDocumento)} text-sm font-bold px-3 py-1`}>
                          {getTipoDocumentoPersonalLabel(doc.tipoDocumento)}
                        </Badge>
                      </div>
                      <CardTitle className="text-2xl font-black text-white mt-4">
                        {doc.nombre}
                      </CardTitle>
                      <CardDescription className="text-base text-teal-300 font-semibold flex items-center gap-2">
                        <User className="h-4 w-4" />
                        {persona ? `${persona.nombre} ${persona.apellidos}` : 'Sin asignar'}
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-4">
                        {/* Info del documento */}
                        <div className="space-y-2 text-sm">
                          {doc.numeroDocumento && (
                            <div className="flex items-center gap-2 text-slate-300">
                              <Hash className="h-4 w-4 text-purple-400" />
                              <span className="font-semibold">No: {doc.numeroDocumento}</span>
                            </div>
                          )}
                          {doc.fechaExpedicion && (
                            <div className="flex items-center gap-2 text-slate-300">
                              <Calendar className="h-4 w-4 text-emerald-400" />
                              <span className="font-semibold">Expedido: {formatDate(doc.fechaExpedicion)}</span>
                            </div>
                          )}
                          {tieneVencimiento && (
                            <div className={`flex items-center gap-2 p-2 rounded-lg border ${getVencimientoBadge(diasVencimiento!)}`}>
                              <AlertTriangle className="h-4 w-4" />
                              <span className="font-bold">{getVencimientoText(diasVencimiento!)}</span>
                              <span className="text-xs">({formatDate(doc.fechaVencimiento!)})</span>
                            </div>
                          )}
                          {doc.entidadEmisora && (
                            <div className="flex items-center gap-2 text-slate-300">
                              <Building2 className="h-4 w-4 text-blue-400" />
                              <span className="font-semibold">{doc.entidadEmisora}</span>
                            </div>
                          )}
                        </div>

                        {/* Archivo si existe */}
                        {doc.archivoUrl && (
                          <div className="text-sm text-slate-400">
                            <p className="font-semibold truncate" title={doc.nombreArchivo}>
                              {doc.nombreArchivo}
                            </p>
                            {doc.tamanioArchivo && <p>{formatFileSize(doc.tamanioArchivo)}</p>}
                          </div>
                        )}

                        {/* Botones */}
                        <div className="flex gap-2 pt-3">
                          {doc.archivoUrl && (
                            <>
                              <Button
                                variant="outline"
                                size="sm"
                                className="flex-1 h-12 text-base font-bold bg-teal-500/10 border-2 border-teal-500/50 text-teal-300 hover:bg-teal-500/20 hover:border-teal-400 hover:text-white"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  window.open(doc.archivoUrl, '_blank')
                                }}
                              >
                                <Eye className="h-5 w-5 mr-2" strokeWidth={2.5} />
                                Ver
                              </Button>
                              <Button
                                variant="outline"
                                size="sm"
                                className="h-12 px-4 text-base font-bold bg-emerald-500/10 border-2 border-emerald-500/50 text-emerald-300 hover:bg-emerald-500/20 hover:border-emerald-400 hover:text-white"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  const link = document.createElement('a')
                                  link.href = doc.archivoUrl!
                                  link.download = doc.nombreArchivo || 'documento'
                                  link.click()
                                }}
                              >
                                <Download className="h-5 w-5" strokeWidth={2.5} />
                              </Button>
                            </>
                          )}
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-12 px-4 text-base font-bold bg-cyan-500/10 border-2 border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400 hover:text-white"
                            onClick={(e) => {
                              e.stopPropagation()
                              setSelectedDocumentoPersonal(doc)
                              setShowDocumentoPersonalModal(true)
                            }}
                          >
                            <Edit className="h-5 w-5" strokeWidth={2.5} />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-12 px-4 text-base font-bold bg-red-500/10 border-2 border-red-500/50 text-red-300 hover:bg-red-500/20 hover:border-red-400 hover:text-white"
                            onClick={(e) => {
                              e.stopPropagation()
                              handleDeleteDocumentoPersonal(doc.id)
                            }}
                          >
                            <Trash2 className="h-5 w-5" strokeWidth={2.5} />
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          ))}
        </div>

        {/* Tabla Dinámica por Tipo de Documento */}
        {documentosPersonales.length > 0 && (
          <div>
            <div
              className="flex flex-col md:flex-row md:items-center justify-between mb-6 gap-4 cursor-pointer"
              onClick={() => setSeccionTablaAbierta(!seccionTablaAbierta)}
            >
              <h2 className="text-4xl font-black text-white flex items-center gap-3">
                <FileText className="h-10 w-10 text-violet-400" strokeWidth={2.5} />
                Tabla de Documentos
                <ChevronDown
                  className={`h-8 w-8 text-violet-400 transition-transform duration-300 ${seccionTablaAbierta ? 'rotate-180' : ''}`}
                  strokeWidth={2.5}
                />
              </h2>
              <div className="flex items-center gap-3" onClick={(e) => e.stopPropagation()}>
                <span className="text-lg text-violet-300 font-semibold">Filtrar por tipo:</span>
                <Select
                  value={filtroTipoDocumento}
                  onValueChange={(value) => setFiltroTipoDocumento(value as TipoDocumentoPersonal | 'todos')}
                >
                  <SelectTrigger className="w-[280px] h-14 text-lg font-bold bg-slate-900/50 border-2 border-violet-500/50 text-white">
                    <SelectValue placeholder="Selecciona un tipo" />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-violet-500/50">
                    <SelectItem value="todos" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Todos los documentos
                    </SelectItem>
                    <SelectItem value="pasaporte" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Pasaportes
                    </SelectItem>
                    <SelectItem value="visa" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Visas
                    </SelectItem>
                    <SelectItem value="ine" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      INE
                    </SelectItem>
                    <SelectItem value="licencia_conducir" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Licencias de Conducir
                    </SelectItem>
                    <SelectItem value="curp" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      CURP
                    </SelectItem>
                    <SelectItem value="acta_nacimiento" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Actas de Nacimiento
                    </SelectItem>
                    <SelectItem value="acta_matrimonio" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Actas de Matrimonio
                    </SelectItem>
                    <SelectItem value="rfc" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      RFC
                    </SelectItem>
                    <SelectItem value="comprobante_domicilio" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Comprobantes de Domicilio
                    </SelectItem>
                    <SelectItem value="poliza_seguro_auto" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Seguros de Auto
                    </SelectItem>
                    <SelectItem value="poliza_seguro_vida" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Seguros de Vida
                    </SelectItem>
                    <SelectItem value="poliza_gastos_medicos" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Gastos Médicos
                    </SelectItem>
                    <SelectItem value="poliza_seguro_hogar" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Seguros de Hogar
                    </SelectItem>
                    <SelectItem value="cartilla_militar" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Cartillas Militares
                    </SelectItem>
                    <SelectItem value="cedula_profesional" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Cédulas Profesionales
                    </SelectItem>
                    <SelectItem value="titulo_profesional" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Títulos Profesionales
                    </SelectItem>
                    <SelectItem value="seguro_social" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Seguro Social
                    </SelectItem>
                    <SelectItem value="otro" className="text-white text-lg font-semibold hover:bg-violet-500/20">
                      Otros
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {seccionTablaAbierta && (
            <>
            <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-violet-500/30 shadow-2xl backdrop-blur-sm">
              <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-violet-500 to-purple-500 opacity-5 rounded-full -mr-32 -mt-32"></div>
              <CardContent className="p-0">
                {(() => {
                  const documentosFiltrados = filtroTipoDocumento === 'todos'
                    ? documentosPersonales
                    : documentosPersonales.filter(d => d.tipoDocumento === filtroTipoDocumento)

                  if (documentosFiltrados.length === 0) {
                    return (
                      <div className="flex flex-col items-center justify-center py-16">
                        <FileText className="h-16 w-16 text-violet-400/50 mb-4" strokeWidth={2} />
                        <p className="text-xl text-violet-300 font-semibold">
                          No hay documentos de este tipo
                        </p>
                      </div>
                    )
                  }

                  return (
                    <div className="overflow-x-auto">
                      <Table>
                        <TableHeader>
                          <TableRow className="border-violet-500/30 hover:bg-transparent">
                            <TableHead className="text-violet-300 font-black text-base py-4">Persona</TableHead>
                            <TableHead className="text-violet-300 font-black text-base py-4">Tipo</TableHead>
                            <TableHead className="text-violet-300 font-black text-base py-4">Nombre</TableHead>
                            <TableHead className="text-violet-300 font-black text-base py-4">Número</TableHead>
                            <TableHead className="text-violet-300 font-black text-base py-4">Expedición</TableHead>
                            <TableHead className="text-violet-300 font-black text-base py-4">Vencimiento</TableHead>
                            <TableHead className="text-violet-300 font-black text-base py-4">Estado</TableHead>
                            <TableHead className="text-violet-300 font-black text-base py-4">Acciones</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {documentosFiltrados.map((doc) => {
                            const persona = personas.find(p => p.id === doc.personaId)
                            const tieneVencimiento = doc.fechaVencimiento
                            const diasVencimiento = tieneVencimiento ? getDiasHastaVencimiento(doc.fechaVencimiento!) : null

                            return (
                              <TableRow
                                key={doc.id}
                                className="border-violet-500/20 hover:bg-violet-500/10 cursor-pointer transition-colors"
                                onClick={() => {
                                  setDocumentoDetalle(doc)
                                  setShowDetalleModal(true)
                                }}
                              >
                                <TableCell className="text-white font-semibold py-4">
                                  <div className="flex items-center gap-2">
                                    <User className="h-4 w-4 text-pink-400" />
                                    {persona ? `${persona.nombre} ${persona.apellidos}` : '-'}
                                  </div>
                                </TableCell>
                                <TableCell className="py-4">
                                  <Badge className={`${getTipoDocumentoPersonalBadge(doc.tipoDocumento)} text-xs font-bold`}>
                                    {getTipoDocumentoPersonalLabel(doc.tipoDocumento)}
                                  </Badge>
                                </TableCell>
                                <TableCell className="text-white font-semibold py-4">
                                  {doc.nombre}
                                </TableCell>
                                <TableCell className="text-slate-300 font-mono py-4">
                                  {doc.numeroDocumento || '-'}
                                </TableCell>
                                <TableCell className="text-slate-300 py-4">
                                  {doc.fechaExpedicion ? formatDate(doc.fechaExpedicion) : '-'}
                                </TableCell>
                                <TableCell className="text-slate-300 py-4">
                                  {doc.fechaVencimiento ? formatDate(doc.fechaVencimiento) : '-'}
                                </TableCell>
                                <TableCell className="py-4">
                                  {tieneVencimiento ? (
                                    <Badge className={`${getVencimientoBadge(diasVencimiento!)} text-xs font-bold`}>
                                      {getVencimientoText(diasVencimiento!)}
                                    </Badge>
                                  ) : (
                                    <Badge className="bg-slate-500/20 text-slate-400 border-slate-500/50 text-xs font-bold">
                                      Sin vencimiento
                                    </Badge>
                                  )}
                                </TableCell>
                                <TableCell className="py-4">
                                  <div className="flex gap-2">
                                    {doc.archivoUrl && (
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        className="h-9 px-3 text-sm font-bold bg-teal-500/10 border border-teal-500/50 text-teal-300 hover:bg-teal-500/20"
                                        onClick={(e) => {
                                          e.stopPropagation()
                                          window.open(doc.archivoUrl, '_blank')
                                        }}
                                      >
                                        <Eye className="h-4 w-4" />
                                      </Button>
                                    )}
                                    <Button
                                      variant="outline"
                                      size="sm"
                                      className="h-9 px-3 text-sm font-bold bg-cyan-500/10 border border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/20"
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        setSelectedDocumentoPersonal(doc)
                                        setShowDocumentoPersonalModal(true)
                                      }}
                                    >
                                      <Edit className="h-4 w-4" />
                                    </Button>
                                    <Button
                                      variant="outline"
                                      size="sm"
                                      className="h-9 px-3 text-sm font-bold bg-red-500/10 border border-red-500/50 text-red-300 hover:bg-red-500/20"
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        handleDeleteDocumentoPersonal(doc.id)
                                      }}
                                    >
                                      <Trash2 className="h-4 w-4" />
                                    </Button>
                                  </div>
                                </TableCell>
                              </TableRow>
                            )
                          })}
                        </TableBody>
                      </Table>
                    </div>
                  )
                })()}
              </CardContent>
            </Card>

            {/* Resumen por tipo */}
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 mt-6">
              {(() => {
                const tiposConDocumentos = documentosPersonales.reduce((acc, doc) => {
                  acc[doc.tipoDocumento] = (acc[doc.tipoDocumento] || 0) + 1
                  return acc
                }, {} as Record<string, number>)

                return Object.entries(tiposConDocumentos)
                  .sort((a, b) => b[1] - a[1])
                  .map(([tipo, cantidad]) => {
                    const IconComponent = getTipoDocumentoPersonalIcon(tipo as TipoDocumentoPersonal)
                    return (
                      <Card
                        key={tipo}
                        className={`cursor-pointer transition-all hover:scale-105 ${
                          filtroTipoDocumento === tipo
                            ? 'bg-violet-500/20 border-violet-400'
                            : 'bg-slate-900/50 border-slate-700 hover:border-violet-500/50'
                        }`}
                        onClick={() => setFiltroTipoDocumento(tipo as TipoDocumentoPersonal)}
                      >
                        <CardContent className="p-4 text-center">
                          <IconComponent className={`h-8 w-8 mx-auto mb-2 ${
                            filtroTipoDocumento === tipo ? 'text-violet-300' : 'text-slate-400'
                          }`} strokeWidth={2} />
                          <p className={`text-2xl font-black ${
                            filtroTipoDocumento === tipo ? 'text-white' : 'text-slate-300'
                          }`}>{cantidad}</p>
                          <p className={`text-xs font-semibold ${
                            filtroTipoDocumento === tipo ? 'text-violet-300' : 'text-slate-500'
                          }`}>{getTipoDocumentoPersonalLabel(tipo as TipoDocumentoPersonal)}</p>
                        </CardContent>
                      </Card>
                    )
                  })
              })()}
              {filtroTipoDocumento !== 'todos' && (
                <Card
                  className="cursor-pointer transition-all hover:scale-105 bg-slate-800/50 border-slate-600 hover:border-slate-500"
                  onClick={() => setFiltroTipoDocumento('todos')}
                >
                  <CardContent className="p-4 text-center flex flex-col items-center justify-center h-full">
                    <X className="h-8 w-8 text-slate-400 mb-2" strokeWidth={2} />
                    <p className="text-sm font-semibold text-slate-400">Limpiar filtro</p>
                  </CardContent>
                </Card>
              )}
            </div>
            </>
            )}
          </div>
        )}
      </div>

      <CuentaModal
        open={showModal}
        onClose={() => {
          setShowModal(false)
          setSelectedCuenta(null)
        }}
        cuenta={selectedCuenta}
        empresaId="personal"
        onSuccess={loadCuentas}
      />

      <DocumentoFinancieroModal
        open={showDocumentoModal}
        onClose={() => setShowDocumentoModal(false)}
        onSuccess={loadDocumentos}
      />

      <PersonaModal
        open={showPersonaModal}
        onClose={() => {
          setShowPersonaModal(false)
          setSelectedPersona(null)
        }}
        persona={selectedPersona}
        onSuccess={() => {
          loadPersonas()
          loadDocumentosPersonales()
        }}
      />

      <DocumentoPersonalModal
        open={showDocumentoPersonalModal}
        onClose={() => {
          setShowDocumentoPersonalModal(false)
          setSelectedDocumentoPersonal(null)
        }}
        documento={selectedDocumentoPersonal}
        personas={personas}
        onSuccess={loadDocumentosPersonales}
      />

      {/* Modal de Detalle del Documento Personal */}
      <Dialog open={showDetalleModal} onOpenChange={setShowDetalleModal}>
        <DialogContent className="max-w-2xl bg-gradient-to-br from-slate-950 via-slate-900 to-blue-950 border-teal-500/30 text-white">
          <DialogHeader>
            <DialogTitle className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-teal-400 to-cyan-400 flex items-center gap-4">
              {documentoDetalle && (
                <>
                  <div className="p-3 rounded-xl bg-gradient-to-br from-teal-500 via-cyan-500 to-blue-500 shadow-lg shadow-teal-500/30">
                    {(() => {
                      const IconComponent = getTipoDocumentoPersonalIcon(documentoDetalle.tipoDocumento)
                      return <IconComponent className="h-8 w-8 text-white" strokeWidth={2.5} />
                    })()}
                  </div>
                  {documentoDetalle.nombre}
                </>
              )}
            </DialogTitle>
          </DialogHeader>

          {documentoDetalle && (() => {
            const persona = personas.find(p => p.id === documentoDetalle.personaId)
            const tieneVencimiento = documentoDetalle.fechaVencimiento
            const diasVencimiento = tieneVencimiento ? getDiasHastaVencimiento(documentoDetalle.fechaVencimiento!) : null

            return (
              <div className="space-y-6 mt-4">
                {/* Tipo de documento y estado */}
                <div className="flex flex-wrap items-center gap-3">
                  <Badge className={`${getTipoDocumentoPersonalBadge(documentoDetalle.tipoDocumento)} text-base font-bold px-4 py-2`}>
                    {getTipoDocumentoPersonalLabel(documentoDetalle.tipoDocumento)}
                  </Badge>
                  {tieneVencimiento && (
                    <Badge className={`${getVencimientoBadge(diasVencimiento!)} text-base font-bold px-4 py-2`}>
                      {getVencimientoText(diasVencimiento!)}
                    </Badge>
                  )}
                </div>

                {/* Información de la persona */}
                <div className="p-4 rounded-xl bg-pink-500/10 border-2 border-pink-500/30">
                  <div className="flex items-center gap-3 text-pink-300">
                    <User className="h-6 w-6" strokeWidth={2.5} />
                    <div>
                      <p className="text-sm font-semibold uppercase tracking-wide">Persona</p>
                      <p className="text-xl font-black text-white">
                        {persona ? `${persona.nombre} ${persona.apellidos}` : 'Sin asignar'}
                      </p>
                      {persona && (
                        <p className="text-sm text-pink-300/70">
                          {getParentescoLabel(persona.parentesco)}
                        </p>
                      )}
                    </div>
                  </div>
                </div>

                {/* Datos del documento en grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {documentoDetalle.numeroDocumento && (
                    <div className="p-4 rounded-xl bg-purple-500/10 border-2 border-purple-500/30">
                      <div className="flex items-center gap-3 text-purple-300">
                        <Hash className="h-5 w-5" strokeWidth={2.5} />
                        <div>
                          <p className="text-sm font-semibold uppercase tracking-wide">Número de Documento</p>
                          <p className="text-lg font-black text-white">{documentoDetalle.numeroDocumento}</p>
                        </div>
                      </div>
                    </div>
                  )}

                  {documentoDetalle.fechaExpedicion && (
                    <div className="p-4 rounded-xl bg-emerald-500/10 border-2 border-emerald-500/30">
                      <div className="flex items-center gap-3 text-emerald-300">
                        <Calendar className="h-5 w-5" strokeWidth={2.5} />
                        <div>
                          <p className="text-sm font-semibold uppercase tracking-wide">Fecha de Expedición</p>
                          <p className="text-lg font-black text-white">{formatDate(documentoDetalle.fechaExpedicion)}</p>
                        </div>
                      </div>
                    </div>
                  )}

                  {documentoDetalle.fechaVencimiento && (
                    <div className={`p-4 rounded-xl border-2 ${
                      diasVencimiento !== null && diasVencimiento <= 30
                        ? 'bg-red-500/10 border-red-500/30'
                        : diasVencimiento !== null && diasVencimiento <= 90
                        ? 'bg-orange-500/10 border-orange-500/30'
                        : 'bg-amber-500/10 border-amber-500/30'
                    }`}>
                      <div className={`flex items-center gap-3 ${
                        diasVencimiento !== null && diasVencimiento <= 30
                          ? 'text-red-300'
                          : diasVencimiento !== null && diasVencimiento <= 90
                          ? 'text-orange-300'
                          : 'text-amber-300'
                      }`}>
                        <AlertTriangle className="h-5 w-5" strokeWidth={2.5} />
                        <div>
                          <p className="text-sm font-semibold uppercase tracking-wide">Fecha de Vencimiento</p>
                          <p className="text-lg font-black text-white">{formatDate(documentoDetalle.fechaVencimiento)}</p>
                        </div>
                      </div>
                    </div>
                  )}

                  {documentoDetalle.lugarExpedicion && (
                    <div className="p-4 rounded-xl bg-blue-500/10 border-2 border-blue-500/30">
                      <div className="flex items-center gap-3 text-blue-300">
                        <MapPin className="h-5 w-5" strokeWidth={2.5} />
                        <div>
                          <p className="text-sm font-semibold uppercase tracking-wide">Lugar de Expedición</p>
                          <p className="text-lg font-black text-white">{documentoDetalle.lugarExpedicion}</p>
                        </div>
                      </div>
                    </div>
                  )}

                  {documentoDetalle.entidadEmisora && (
                    <div className="p-4 rounded-xl bg-cyan-500/10 border-2 border-cyan-500/30">
                      <div className="flex items-center gap-3 text-cyan-300">
                        <Building2 className="h-5 w-5" strokeWidth={2.5} />
                        <div>
                          <p className="text-sm font-semibold uppercase tracking-wide">Entidad Emisora</p>
                          <p className="text-lg font-black text-white">{documentoDetalle.entidadEmisora}</p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Notas */}
                {documentoDetalle.notas && (
                  <div className="p-4 rounded-xl bg-slate-500/10 border-2 border-slate-500/30">
                    <div className="flex items-start gap-3 text-slate-300">
                      <FileText className="h-5 w-5 mt-1" strokeWidth={2.5} />
                      <div>
                        <p className="text-sm font-semibold uppercase tracking-wide">Notas</p>
                        <p className="text-base text-white mt-1 whitespace-pre-wrap">{documentoDetalle.notas}</p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Archivo adjunto */}
                {documentoDetalle.archivoUrl && (
                  <div className="p-4 rounded-xl bg-teal-500/10 border-2 border-teal-500/30">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3 text-teal-300">
                        <FileText className="h-5 w-5" strokeWidth={2.5} />
                        <div>
                          <p className="text-sm font-semibold uppercase tracking-wide">Archivo Adjunto</p>
                          <p className="text-base text-white">{documentoDetalle.nombreArchivo}</p>
                          {documentoDetalle.tamanioArchivo && (
                            <p className="text-sm text-teal-300/70">{formatFileSize(documentoDetalle.tamanioArchivo)}</p>
                          )}
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-10 text-base font-bold bg-teal-500/10 border-2 border-teal-500/50 text-teal-300 hover:bg-teal-500/20 hover:border-teal-400 hover:text-white"
                          onClick={() => window.open(documentoDetalle.archivoUrl, '_blank')}
                        >
                          <Eye className="h-5 w-5 mr-2" strokeWidth={2.5} />
                          Ver
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-10 text-base font-bold bg-emerald-500/10 border-2 border-emerald-500/50 text-emerald-300 hover:bg-emerald-500/20 hover:border-emerald-400 hover:text-white"
                          onClick={() => {
                            const link = document.createElement('a')
                            link.href = documentoDetalle.archivoUrl!
                            link.download = documentoDetalle.nombreArchivo || 'documento'
                            link.click()
                          }}
                        >
                          <Download className="h-5 w-5 mr-2" strokeWidth={2.5} />
                          Descargar
                        </Button>
                      </div>
                    </div>
                  </div>
                )}

                {/* Botones de acción */}
                <div className="flex gap-3 pt-4 border-t border-slate-700">
                  <Button
                    className="flex-1 h-14 text-lg font-bold bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-700 hover:to-blue-700 text-white"
                    onClick={() => {
                      setShowDetalleModal(false)
                      setSelectedDocumentoPersonal(documentoDetalle)
                      setShowDocumentoPersonalModal(true)
                    }}
                  >
                    <Edit className="h-6 w-6 mr-2" strokeWidth={2.5} />
                    Editar Documento
                  </Button>
                  <Button
                    variant="outline"
                    className="h-14 px-6 text-lg font-bold bg-slate-800/50 border-2 border-slate-600 text-slate-300 hover:bg-slate-700 hover:text-white"
                    onClick={() => setShowDetalleModal(false)}
                  >
                    Cerrar
                  </Button>
                </div>
              </div>
            )
          })()}
        </DialogContent>
      </Dialog>
    </MainLayout>
  )
}
