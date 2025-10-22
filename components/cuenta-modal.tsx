'use client'

import { useState, useEffect } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createCuenta, updateCuenta, uploadCuentaLogo } from '@/lib/firestore'
import type { CuentaBancaria, CuentaBancariaFormData, Moneda, TipoCuenta } from '@/lib/types'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  CreditCard,
  Landmark,
  Hash,
  DollarSign,
  Calendar,
  FileText,
  User,
  MapPin,
  Upload,
  X
} from 'lucide-react'
import Image from 'next/image'

interface CuentaModalProps {
  open: boolean
  onClose: () => void
  cuenta?: CuentaBancaria | null
  empresaId: string
  onSuccess: () => void
}

export function CuentaModal({ open, onClose, cuenta, empresaId, onSuccess }: CuentaModalProps) {
  const { user } = useAuth()
  const [loading, setLoading] = useState(false)
  const [logoFile, setLogoFile] = useState<File | null>(null)
  const [logoPreview, setLogoPreview] = useState<string | null>(null)
  const [formData, setFormData] = useState<CuentaBancariaFormData>({
    nombre: '',
    banco: '',
    numeroCuenta: '',
    clabe: '',
    tipoCuenta: 'cheques',
    moneda: 'MXN',
    saldoInicial: 0,
    beneficiario: '',
    sucursal: '',
    limiteCredito: 0,
    diaCorte: undefined,
    diaLimitePago: undefined,
    notas: '',
    logo: '',
  })

  useEffect(() => {
    if (cuenta) {
      setFormData({
        nombre: cuenta.nombre,
        banco: cuenta.banco,
        numeroCuenta: cuenta.numeroCuenta,
        clabe: cuenta.clabe || '',
        tipoCuenta: cuenta.tipoCuenta,
        moneda: cuenta.moneda,
        saldoInicial: cuenta.saldoInicial,
        beneficiario: cuenta.beneficiario || '',
        sucursal: cuenta.sucursal || '',
        limiteCredito: cuenta.limiteCredito || 0,
        diaCorte: cuenta.diaCorte,
        diaLimitePago: cuenta.diaLimitePago,
        notas: cuenta.notas || '',
        logo: cuenta.logo || '',
      })
      setLogoPreview(cuenta.logo || null)
      setLogoFile(null)
    } else {
      setFormData({
        nombre: '',
        banco: '',
        numeroCuenta: '',
        clabe: '',
        tipoCuenta: 'cheques',
        moneda: 'MXN',
        saldoInicial: 0,
        beneficiario: '',
        sucursal: '',
        limiteCredito: 0,
        diaCorte: undefined,
        diaLimitePago: undefined,
        notas: '',
        logo: '',
      })
      setLogoPreview(null)
      setLogoFile(null)
    }
  }, [cuenta, open])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user) return

    try {
      setLoading(true)
      let logoUrl = formData.logo || ''

      // Limpiar campos undefined, null y strings vacíos para Firestore
      const dataToClean = { ...formData, logo: logoUrl }
      const cleanData: Record<string, unknown> = {}

      Object.entries(dataToClean).forEach(([key, value]) => {
        // Solo incluir valores que no sean undefined, null, o string vacío
        if (value !== undefined && value !== null && value !== '') {
          cleanData[key] = value
        }
      })

      if (cuenta) {
        // Editar cuenta existente
        if (logoFile) {
          // Si hay un nuevo logo, subirlo
          logoUrl = await uploadCuentaLogo(logoFile, cuenta.id)
          cleanData.logo = logoUrl
        }
        await updateCuenta(cuenta.id, cleanData as unknown as Partial<CuentaBancariaFormData>)
      } else {
        // Crear nueva cuenta
        const cuentaId = await createCuenta(user.uid, empresaId, cleanData as unknown as CuentaBancariaFormData)

        // Si hay logo, subirlo y actualizar
        if (logoFile) {
          logoUrl = await uploadCuentaLogo(logoFile, cuentaId)
          const logoUpdate: Record<string, string> = { logo: logoUrl }
          await updateCuenta(cuentaId, logoUpdate)
        }
      }
      onSuccess()
      onClose()
    } catch (error) {
      console.error('Error al guardar cuenta:', error)
      alert(`Error al guardar la cuenta: ${error instanceof Error ? error.message : 'Error desconocido'}`)
    } finally {
      setLoading(false)
    }
  }

  const handleChange = (field: keyof CuentaBancariaFormData, value: string | number) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
  }

  const handleLogoChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      // Validar que sea imagen
      if (!file.type.startsWith('image/')) {
        alert('Por favor selecciona un archivo de imagen')
        return
      }

      // Validar tamaño (máx 2MB)
      if (file.size > 2 * 1024 * 1024) {
        alert('La imagen debe ser menor a 2MB')
        return
      }

      setLogoFile(file)

      // Crear preview
      const reader = new FileReader()
      reader.onloadend = () => {
        setLogoPreview(reader.result as string)
      }
      reader.readAsDataURL(file)
    }
  }

  const handleRemoveLogo = () => {
    setLogoFile(null)
    setLogoPreview(null)
    setFormData(prev => ({ ...prev, logo: '' }))
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-[60vw] max-h-[85vh] overflow-y-auto bg-gradient-to-br from-slate-950 via-blue-950 to-slate-950 border-cyan-500/30 shadow-2xl shadow-cyan-500/20">
        <DialogHeader className="space-y-4 pb-6 border-b border-cyan-500/20">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-gradient-to-br from-cyan-500 via-blue-500 to-indigo-500 shadow-xl shadow-cyan-500/30">
              <CreditCard className="h-10 w-10 text-white" strokeWidth={2.5} />
            </div>
            <div>
              <DialogTitle className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400">
                {cuenta ? 'Editar Cuenta Bancaria' : 'Nueva Cuenta Bancaria'}
              </DialogTitle>
              <DialogDescription className="text-lg text-slate-400 font-semibold mt-1">
                {cuenta
                  ? 'Actualiza la información de la cuenta bancaria'
                  : 'Completa los datos de la nueva cuenta'}
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="grid gap-6 py-6">
            {/* Primera fila: Nombre */}
            <div className="grid gap-4">
              <Label htmlFor="nombre" className="text-2xl font-black text-white flex items-center gap-3">
                <CreditCard className="h-7 w-7 text-cyan-400" />
                Nombre de la Cuenta *
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <CreditCard className="h-8 w-8 text-cyan-400" />
                </div>
                <Input
                  id="nombre"
                  placeholder="Ej: Cuenta Cheques Principal"
                  value={formData.nombre}
                  onChange={(e) => handleChange('nombre', e.target.value)}
                  required
                  disabled={loading}
                  className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-cyan-500 focus:ring-cyan-500/20"
                />
              </div>
            </div>

            {/* Segunda fila: Banco y Tipo de Cuenta */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="banco" className="text-2xl font-black text-white flex items-center gap-3">
                  <Landmark className="h-7 w-7 text-blue-400" />
                  Banco *
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Landmark className="h-8 w-8 text-blue-400" />
                  </div>
                  <Input
                    id="banco"
                    placeholder="Ej: BBVA"
                    value={formData.banco}
                    onChange={(e) => handleChange('banco', e.target.value)}
                    required
                    disabled={loading}
                    className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-blue-500 focus:ring-blue-500/20"
                  />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="tipoCuenta" className="text-2xl font-black text-white flex items-center gap-3">
                  <FileText className="h-7 w-7 text-purple-400" />
                  Tipo de Cuenta *
                </Label>
                <Select
                  value={formData.tipoCuenta}
                  onValueChange={(value) => handleChange('tipoCuenta', value as TipoCuenta)}
                  disabled={loading}
                >
                  <SelectTrigger className="h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white px-5 py-10 focus:border-purple-500 focus:ring-purple-500/20">
                    <div className="flex items-center gap-3">
                      <FileText className="h-8 w-8 text-purple-400" />
                      <SelectValue />
                    </div>
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-slate-700">
                    <SelectItem value="cheques" className="!text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                      Cheques
                    </SelectItem>
                    <SelectItem value="credito" className="!text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                      Crédito
                    </SelectItem>
                    <SelectItem value="prestamo" className="!text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                      Préstamo
                    </SelectItem>
                    <SelectItem value="ahorro" className="!text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                      Ahorro
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Logo del Banco */}
            <div className="grid gap-4">
              <Label htmlFor="logo" className="text-2xl font-black text-white flex items-center gap-3">
                <Upload className="h-7 w-7 text-cyan-400" />
                Logo del Banco
              </Label>
              <div className="flex flex-col gap-4">
                {logoPreview ? (
                  <div className="relative w-40 h-40 border-2 border-cyan-500/30 rounded-2xl overflow-hidden bg-slate-900/50 shadow-xl shadow-cyan-500/20">
                    <Image
                      src={logoPreview}
                      alt="Logo preview"
                      fill
                      className="object-contain p-3"
                    />
                    <button
                      type="button"
                      onClick={handleRemoveLogo}
                      className="absolute top-2 right-2 bg-red-500 hover:bg-red-600 text-white rounded-full p-2 transition-all shadow-lg hover:scale-110"
                      disabled={loading}
                    >
                      <X className="h-5 w-5" />
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center gap-4">
                    <label
                      htmlFor="logo-upload"
                      className="flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl cursor-pointer transition-all shadow-lg shadow-cyan-500/30 hover:shadow-cyan-500/50 font-bold text-base transform hover:scale-105"
                    >
                      <Upload className="h-6 w-6" />
                      <span>Subir Logo</span>
                    </label>
                    <input
                      id="logo-upload"
                      type="file"
                      accept="image/*"
                      onChange={handleLogoChange}
                      className="hidden"
                      disabled={loading}
                    />
                  </div>
                )}
              </div>
            </div>

            {/* Tercera fila: Número de Cuenta y CLABE */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="numeroCuenta" className="text-2xl font-black text-white flex items-center gap-3">
                  <Hash className="h-7 w-7 text-emerald-400" />
                  Número de Cuenta *
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Hash className="h-8 w-8 text-emerald-400" />
                  </div>
                  <Input
                    id="numeroCuenta"
                    placeholder="1234567890"
                    value={formData.numeroCuenta}
                    onChange={(e) => handleChange('numeroCuenta', e.target.value)}
                    required
                    disabled={loading}
                    className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-emerald-500 focus:ring-emerald-500/20"
                  />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="clabe" className="text-2xl font-black text-white flex items-center gap-3">
                  <Hash className="h-7 w-7 text-teal-400" />
                  CLABE
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Hash className="h-8 w-8 text-teal-400" />
                  </div>
                  <Input
                    id="clabe"
                    placeholder="012345678901234567"
                    value={formData.clabe}
                    onChange={(e) => handleChange('clabe', e.target.value)}
                    maxLength={18}
                    disabled={loading}
                    className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-teal-500 focus:ring-teal-500/20"
                  />
                </div>
              </div>
            </div>

            {/* Cuarta fila: Moneda y Saldo Inicial */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="moneda" className="text-2xl font-black text-white flex items-center gap-3">
                  <DollarSign className="h-7 w-7 text-yellow-400" />
                  Moneda *
                </Label>
                <Select
                  value={formData.moneda}
                  onValueChange={(value) => handleChange('moneda', value as Moneda)}
                  disabled={loading}
                >
                  <SelectTrigger className="h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white px-5 py-10 focus:border-yellow-500 focus:ring-yellow-500/20">
                    <div className="flex items-center gap-3">
                      <DollarSign className="h-8 w-8 text-yellow-400" />
                      <SelectValue />
                    </div>
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-slate-700">
                    <SelectItem value="MXN" className="!text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                      🇲🇽 Peso Mexicano (MXN)
                    </SelectItem>
                    <SelectItem value="USD" className="!text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                      🇺🇸 Dólar Americano (USD)
                    </SelectItem>
                    <SelectItem value="EUR" className="!text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                      🇪🇺 Euro (EUR)
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="saldoInicial" className="text-2xl font-black text-white flex items-center gap-3">
                  <DollarSign className="h-7 w-7 text-green-400" />
                  Saldo Inicial *
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <DollarSign className="h-8 w-8 text-green-400" />
                  </div>
                  <Input
                    id="saldoInicial"
                    type="number"
                    step="0.01"
                    value={formData.saldoInicial}
                    onChange={(e) => handleChange('saldoInicial', parseFloat(e.target.value) || 0)}
                    required
                    disabled={loading}
                    className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-green-500 focus:ring-green-500/20"
                  />
                </div>
              </div>
            </div>

            {/* Quinta fila: Beneficiario y Sucursal */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="beneficiario" className="text-2xl font-black text-white flex items-center gap-3">
                  <User className="h-7 w-7 text-pink-400" />
                  Beneficiario
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <User className="h-8 w-8 text-pink-400" />
                  </div>
                  <Input
                    id="beneficiario"
                    value={formData.beneficiario}
                    onChange={(e) => handleChange('beneficiario', e.target.value)}
                    disabled={loading}
                    className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-pink-500 focus:ring-pink-500/20"
                  />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="sucursal" className="text-2xl font-black text-white flex items-center gap-3">
                  <MapPin className="h-7 w-7 text-orange-400" />
                  Sucursal
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <MapPin className="h-8 w-8 text-orange-400" />
                  </div>
                  <Input
                    id="sucursal"
                    value={formData.sucursal}
                    onChange={(e) => handleChange('sucursal', e.target.value)}
                    disabled={loading}
                    className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-orange-500 focus:ring-orange-500/20"
                  />
                </div>
              </div>
            </div>

            {/* Campos específicos para tarjetas de crédito */}
            {formData.tipoCuenta === 'credito' && (
              <>
                <div className="grid gap-4">
                  <Label htmlFor="limiteCredito" className="text-2xl font-black text-white flex items-center gap-3">
                    <DollarSign className="h-7 w-7 text-red-400" />
                    Límite de Crédito
                  </Label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                      <DollarSign className="h-8 w-8 text-red-400" />
                    </div>
                    <Input
                      id="limiteCredito"
                      type="number"
                      step="0.01"
                      placeholder="0.00"
                      value={formData.limiteCredito || 0}
                      onChange={(e) => handleChange('limiteCredito', parseFloat(e.target.value) || 0)}
                      disabled={loading}
                      className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-red-500 focus:ring-red-500/20"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-6">
                  <div className="grid gap-4">
                    <Label htmlFor="diaCorte" className="text-2xl font-black text-white flex items-center gap-3">
                      <Calendar className="h-7 w-7 text-indigo-400" />
                      Día de Corte
                    </Label>
                    <Select
                      value={formData.diaCorte?.toString() || ''}
                      onValueChange={(value) => handleChange('diaCorte', parseInt(value))}
                      disabled={loading}
                    >
                      <SelectTrigger className="h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white px-5 py-10 focus:border-indigo-500 focus:ring-indigo-500/20">
                        <div className="flex items-center gap-3">
                          <Calendar className="h-8 w-8 text-indigo-400" />
                          <SelectValue placeholder="Seleccionar día" />
                        </div>
                      </SelectTrigger>
                      <SelectContent className="bg-slate-900 border-slate-700 max-h-80">
                        {Array.from({ length: 31 }, (_, i) => i + 1).map((dia) => (
                          <SelectItem key={dia} value={dia.toString()} className="!text-xl font-bold text-white hover:bg-slate-800 cursor-pointer py-3">
                            Día {dia}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="grid gap-4">
                    <Label htmlFor="diaLimitePago" className="text-2xl font-black text-white flex items-center gap-3">
                      <Calendar className="h-7 w-7 text-violet-400" />
                      Día Límite de Pago
                    </Label>
                    <Select
                      value={formData.diaLimitePago?.toString() || ''}
                      onValueChange={(value) => handleChange('diaLimitePago', parseInt(value))}
                      disabled={loading}
                    >
                      <SelectTrigger className="h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white px-5 py-10 focus:border-violet-500 focus:ring-violet-500/20">
                        <div className="flex items-center gap-3">
                          <Calendar className="h-8 w-8 text-violet-400" />
                          <SelectValue placeholder="Seleccionar día" />
                        </div>
                      </SelectTrigger>
                      <SelectContent className="bg-slate-900 border-slate-700 max-h-80">
                        {Array.from({ length: 31 }, (_, i) => i + 1).map((dia) => (
                          <SelectItem key={dia} value={dia.toString()} className="!text-xl font-bold text-white hover:bg-slate-800 cursor-pointer py-3">
                            Día {dia}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </>
            )}

            {/* Notas */}
            <div className="grid gap-4">
              <Label htmlFor="notas" className="text-2xl font-black text-white flex items-center gap-3">
                <FileText className="h-7 w-7 text-slate-400" />
                Notas
              </Label>
              <div className="relative">
                <div className="absolute top-6 left-0 pl-5 flex items-start pointer-events-none">
                  <FileText className="h-8 w-8 text-slate-400" />
                </div>
                <Input
                  id="notas"
                  placeholder="Notas adicionales sobre esta cuenta"
                  value={formData.notas}
                  onChange={(e) => handleChange('notas', e.target.value)}
                  disabled={loading}
                  className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-slate-500 focus:ring-slate-500/20"
                />
              </div>
            </div>
          </div>

          <DialogFooter className="gap-4 pt-8 border-t border-slate-700">
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
              disabled={loading}
              className="h-20 px-12 text-2xl font-black border-2 border-slate-600 bg-slate-900/50 text-slate-300 hover:bg-slate-800 hover:text-white"
            >
              Cancelar
            </Button>
            <Button
              type="submit"
              disabled={loading}
              className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:via-blue-500 hover:to-indigo-500 text-white shadow-lg shadow-cyan-500/30 hover:shadow-cyan-500/50 transform hover:scale-105 transition-all"
            >
              {loading ? 'Guardando...' : cuenta ? 'Actualizar Cuenta' : 'Crear Cuenta'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
