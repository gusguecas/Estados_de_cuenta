'use client'

import { useState, useCallback } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createMovimiento, getCategorias, createCategoria } from '@/lib/firestore'
import type { Categoria, TipoMovimiento, MovimientoFormData } from '@/lib/types'
import * as XLSX from 'xlsx'
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Upload, FileSpreadsheet, AlertCircle } from 'lucide-react'

interface ImportarMovimientosModalProps {
  open: boolean
  onClose: () => void
  cuentaId: string
  onSuccess: () => void
}

interface MovimientoImportado extends MovimientoFormData {
  error?: string
}

export function ImportarMovimientosModal({
  open,
  onClose,
  cuentaId,
  onSuccess
}: ImportarMovimientosModalProps) {
  const { user } = useAuth()
  const [loading, setLoading] = useState(false)
  const [movimientos, setMovimientos] = useState<MovimientoImportado[]>([])
  const [categorias, setCategorias] = useState<Categoria[]>([])

  const loadCategorias = useCallback(async () => {
    if (!user) return
    try {
      const data = await getCategorias(user.uid)
      setCategorias(data)
    } catch (error) {
      console.error('Error al cargar categorías:', error)
    }
  }, [user])

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    try {
      await loadCategorias()

      const data = await file.arrayBuffer()
      const workbook = XLSX.read(data)
      const worksheet = workbook.Sheets[workbook.SheetNames[0]]
      const jsonData = XLSX.utils.sheet_to_json(worksheet)

      console.log('📊 Total de filas:', jsonData.length)
      if (jsonData.length > 0) {
        console.log('📋 Columnas detectadas:', Object.keys(jsonData[0] as Record<string, unknown>))
        console.log('📝 Primera fila de ejemplo:', jsonData[0])
        console.log('💰 Primeras 10 filas con valores CARGO/ABONO:')
        jsonData.slice(0, 10).forEach((row, idx: number) => {
          const r = row as Record<string, unknown>
          console.log(`  Fila ${idx + 1}: CONCEPTO="${r.CONCEPTO}", CARGO=${r.CARGO || 'N/A'}, ABONO=${r.ABONO || 'N/A'}`)
        })
      }

      // Crear un map para rastrear las categorías creadas en este proceso
      const categoriasCreadas = new Map<string, string>()

      // Array local de categorías (incluye existentes + nuevas)
      const todasLasCategorias = [...categorias]

      const movimientosImportados: MovimientoImportado[] = []

      // Procesar secuencialmente para evitar race conditions
      for (let index = 0; index < jsonData.length; index++) {
        const row = jsonData[index] as Record<string, unknown>

        if (index === 0) {
          console.log('🔍 Procesando primera fila:', row)
        }

        // Intentar obtener la fecha de diferentes columnas posibles
        const fechaValue = row.FECHA || row.Fecha || row.fecha

        // Función para redondear a 2 decimales y evitar errores de precisión
        const roundMoney = (value: number) => Math.round(value * 100) / 100

        // Determinar tipo y monto basado en Cargo/Abono o PAGO
        const cargo = roundMoney(parseFloat(String(row.CARGO || row.Cargo || row.cargo || 0)))
        const abono = roundMoney(parseFloat(String(row.ABONO || row.Abono || row.abono || 0)))
        const pago = roundMoney(parseFloat(String(row.PAGO || row.Pago || row.pago || 0)))

        let tipo: TipoMovimiento = 'egreso'
        let monto = 0

        // Si tiene columnas Cargo/Abono separadas
        if (abono > 0) {
          tipo = 'ingreso'
          monto = abono
        } else if (cargo > 0) {
          tipo = 'egreso'
          monto = cargo
        } else if (pago > 0) {
          // Si solo tiene columna PAGO, asumimos que es un egreso
          tipo = 'egreso'
          monto = pago
        }

        const categoriaValue = String(
          row.Categoria || row.categoria || row.CATEGORIA ||
          row.Categoría || row.categoría || row.CATEGORÍA ||
          row.Tipo || row.tipo || row.TIPO ||
          ''
        )

        if (index < 5) {
          console.log(`📌 Fila ${index + 1}: Categoría detectada = "${categoriaValue}"`)
        }

        // Buscar o crear categoría
        let categoriaId = ''
        if (categoriaValue && user) {
          const categoriaKey = `${categoriaValue.toLowerCase()}-${tipo}`

          // Buscar en categorías existentes o recién creadas
          const categoriaExistente = todasLasCategorias.find(c =>
            c.nombre.toLowerCase() === categoriaValue.toLowerCase() && c.tipo === tipo
          )

          if (categoriaExistente) {
            categoriaId = categoriaExistente.id
            if (index < 5) {
              console.log(`✅ Fila ${index + 1}: Categoría existente encontrada: ${categoriaExistente.nombre} (${categoriaId})`)
            }
          } else if (categoriasCreadas.has(categoriaKey)) {
            // Buscar en las creadas durante esta importación
            categoriaId = categoriasCreadas.get(categoriaKey)!
            if (index < 5) {
              console.log(`♻️ Fila ${index + 1}: Categoría ya creada en esta importación: ${categoriaValue} (${categoriaId})`)
            }
          } else {
            // Crear nueva categoría
            try {
              categoriaId = await createCategoria(user.uid, categoriaValue.trim(), tipo)
              categoriasCreadas.set(categoriaKey, categoriaId)

              // Agregar al array local para que esté disponible para las siguientes filas
              const nuevaCategoria: Categoria = {
                id: categoriaId,
                nombre: categoriaValue.trim(),
                tipo: tipo,
                userId: user.uid,
                activo: true
              }
              todasLasCategorias.push(nuevaCategoria)

              if (index < 5) {
                console.log(`🆕 Fila ${index + 1}: Categoría creada: ${categoriaValue} (${categoriaId})`)
              }
            } catch (error) {
              console.error(`❌ Error al crear categoría "${categoriaValue}":`, error)
            }
          }
        }

        const movimiento: MovimientoImportado = {
          fecha: parseDate(fechaValue),
          tipo,
          monto,
          descripcion: String(row.CONCEPTO || row.Concepto || row.concepto || row.Descripcion || row.descripcion || ''),
          categoriaId,
          referencia: String(row['No Cheque'] || row['no cheque'] || row.Referencia || row.referencia || ''),
          beneficiario: '',
          comentarios: String(row.COMENTARIOS || row.Comentarios || row.comentarios || ''),
          notas: String(row.Notas || row.notas || ''),
        }

        // Validar
        if (!movimiento.fecha || movimiento.fecha === 'Invalid Date') {
          movimiento.error = 'Fecha inválida'
        } else if (!movimiento.monto || movimiento.monto <= 0) {
          movimiento.error = 'Debe tener Cargo o Abono mayor a 0'
        } else if (!movimiento.descripcion) {
          movimiento.error = 'Descripción es requerida'
        }

        movimientosImportados.push(movimiento)
      }

      // Actualizar el estado de categorías para que React re-renderice la vista previa
      setCategorias(todasLasCategorias)

      console.log(`✅ Proceso completado: ${movimientosImportados.length} movimientos procesados`)
      console.log(`📁 Total de categorías disponibles: ${todasLasCategorias.length}`)

      setMovimientos(movimientosImportados)
    } catch (error) {
      console.error('Error al leer archivo:', error)
      alert('Error al leer el archivo. Verifica que el formato sea correcto (Excel o CSV).')
    }
  }

  const parseDate = (value: unknown): string => {
    if (!value) {
      console.log('⚠️ Fecha vacía')
      return 'Invalid Date'
    }

    console.log('🔍 Parseando fecha:', value, 'Tipo:', typeof value)

    try {
      // Si es un número (fecha de Excel)
      if (typeof value === 'number') {
        // Excel almacena fechas como días desde 1900-01-01 (pero con un bug de año bisiesto)
        // Usar UTC para evitar problemas de zona horaria
        const excelEpoch = Date.UTC(1899, 11, 30) // 30 de diciembre de 1899
        const dateMs = excelEpoch + value * 86400000
        const date = new Date(dateMs)

        // Usar UTC para evitar desfases de zona horaria
        const year = date.getUTCFullYear()
        const month = String(date.getUTCMonth() + 1).padStart(2, '0')
        const day = String(date.getUTCDate()).padStart(2, '0')

        const result = `${year}-${month}-${day}`
        console.log('✅ Fecha parseada (número Excel):', result)
        return result
      }

      // Si es string, intentar parsear diferentes formatos
      if (typeof value === 'string') {
        const trimmedValue = value.trim()

        // Formato: DD/MM/YYYY, HH:MM:SS o DD/MM/YYYY, etc
        const ddmmyyyyWithComma = trimmedValue.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/)
        if (ddmmyyyyWithComma) {
          const [, day, month, year] = ddmmyyyyWithComma
          const result = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`
          console.log('✅ Fecha parseada (DD/MM/YYYY con/sin hora):', result)
          return result
        }

        // Formato DD-MM-YYYY
        const ddmmyyyyDashMatch = trimmedValue.match(/^(\d{1,2})-(\d{1,2})-(\d{4})/)
        if (ddmmyyyyDashMatch) {
          const [, day, month, year] = ddmmyyyyDashMatch
          const result = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`
          console.log('✅ Fecha parseada (DD-MM-YYYY):', result)
          return result
        }

        // Formato YYYY-MM-DD (ya está correcto)
        const yyyymmddMatch = trimmedValue.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/)
        if (yyyymmddMatch) {
          const [, year, month, day] = yyyymmddMatch
          const result = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`
          console.log('✅ Fecha parseada (YYYY-MM-DD):', result)
          return result
        }

        console.log('⚠️ Ningún formato regex coincidió. Valor:', trimmedValue)
      }

      // Si es un objeto Date
      if (value instanceof Date && !isNaN(value.getTime())) {
        const year = value.getFullYear()
        const month = String(value.getMonth() + 1).padStart(2, '0')
        const day = String(value.getDate()).padStart(2, '0')
        const result = `${year}-${month}-${day}`
        console.log('✅ Fecha parseada (Date object):', result)
        return result
      }
    } catch (error) {
      console.error('❌ Error al parsear fecha:', value, error)
    }

    console.log('❌ Fecha inválida final. Valor recibido:', value, 'Tipo:', typeof value)
    return 'Invalid Date'
  }


  const handleImportar = async () => {
    if (!user) return

    const movimientosValidos = movimientos.filter(m => !m.error)
    if (movimientosValidos.length === 0) {
      alert('No hay movimientos válidos para importar')
      return
    }

    // Ordenar por fecha ANTES de importar para calcular saldos correctamente
    const movimientosOrdenados = [...movimientosValidos].sort((a, b) => {
      const fechaA = new Date(a.fecha).getTime()
      const fechaB = new Date(b.fecha).getTime()
      return fechaA - fechaB // Del más antiguo al más reciente
    })

    console.log('📅 Importando movimientos en orden cronológico:')
    console.log(`  Primero: ${movimientosOrdenados[0].fecha}`)
    console.log(`  Último: ${movimientosOrdenados[movimientosOrdenados.length - 1].fecha}`)

    try {
      setLoading(true)

      for (const movimiento of movimientosOrdenados) {
        await createMovimiento(user.uid, cuentaId, movimiento)
      }

      // Recalcular todos los saldos para asegurar que estén correctos
      console.log('🔄 Recalculando saldos...')
      const { recalcularSaldos } = await import('@/lib/firestore')
      await recalcularSaldos(cuentaId)
      console.log('✅ Saldos recalculados correctamente')

      alert(`Se importaron ${movimientosValidos.length} movimientos exitosamente`)
      onSuccess()
      onClose()
      setMovimientos([])
    } catch (error) {
      console.error('Error al importar movimientos:', error)
      alert('Error al importar movimientos')
    } finally {
      setLoading(false)
    }
  }

  const formatMoney = (amount: number) => {
    return new Intl.NumberFormat('es-MX', {
      style: 'currency',
      currency: 'MXN'
    }).format(amount)
  }

  const movimientosValidos = movimientos.filter(m => !m.error).length
  const movimientosConError = movimientos.filter(m => m.error).length

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-6xl max-h-[90vh] overflow-y-auto bg-gradient-to-br from-slate-950 via-blue-950 to-slate-900 border-cyan-500/30" aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle className="text-5xl font-bold text-white mb-6">Importar Movimientos desde Excel/CSV</DialogTitle>
        </DialogHeader>

        <div className="space-y-6">
          <div className="bg-slate-900/50 border border-cyan-500/30 rounded-xl p-8 space-y-6">
            <p className="font-bold text-3xl text-white">📋 Instrucciones para importar movimientos</p>

            <div className="space-y-4">
                <p className="text-2xl text-gray-300">
                  <strong className="text-cyan-400">1. Formato del archivo:</strong> El archivo puede ser Excel (.xlsx o .xls) o CSV (.csv)
                </p>

                <p className="text-2xl text-gray-300">
                  <strong className="text-cyan-400">2. Orden de las columnas (de izquierda a derecha):</strong>
                </p>

                <div className="ml-8 space-y-3 text-xl">
                  <div className="flex gap-4">
                    <span className="text-emerald-400 font-bold min-w-[220px]">1. Fecha:</span>
                    <span className="text-gray-300">Fecha del movimiento (formato: DD/MM/AAAA o AAAA-MM-DD)</span>
                  </div>
                  <div className="flex gap-4">
                    <span className="text-purple-400 font-bold min-w-[220px]">2. No Cheque:</span>
                    <span className="text-gray-300">Número de cheque o referencia (opcional)</span>
                  </div>
                  <div className="flex gap-4">
                    <span className="text-purple-400 font-bold min-w-[220px]">3. Categoría:</span>
                    <span className="text-gray-300">Categoría del movimiento (opcional, se crea automáticamente)</span>
                  </div>
                  <div className="flex gap-4">
                    <span className="text-emerald-400 font-bold min-w-[220px]">4. Descripción:</span>
                    <span className="text-gray-300">Descripción del movimiento (obligatorio)</span>
                  </div>
                  <div className="flex gap-4">
                    <span className="text-emerald-400 font-bold min-w-[220px]">5. Abono:</span>
                    <span className="text-gray-300">Monto del ingreso/entrada (dejar vacío si es cargo)</span>
                  </div>
                  <div className="flex gap-4">
                    <span className="text-emerald-400 font-bold min-w-[220px]">6. Cargo:</span>
                    <span className="text-gray-300">Monto del egreso/salida (dejar vacío si es abono)</span>
                  </div>
                  <div className="flex gap-4">
                    <span className="text-purple-400 font-bold min-w-[220px]">7. Saldo:</span>
                    <span className="text-gray-300">Saldo después del movimiento (opcional, se calcula automáticamente)</span>
                  </div>
                  <div className="flex gap-4">
                    <span className="text-purple-400 font-bold min-w-[220px]">8. Comentarios:</span>
                    <span className="text-gray-300">Comentarios adicionales (opcional)</span>
                  </div>
                  <div className="flex gap-4">
                    <span className="text-purple-400 font-bold min-w-[220px]">9. Notas:</span>
                    <span className="text-gray-300">Notas internas (opcional)</span>
                  </div>
                </div>

                <div className="mt-6 p-6 bg-blue-950/50 border border-blue-500/30 rounded-lg space-y-3">
                  <p className="text-xl text-blue-300">
                    <strong>💡 Notas importantes:</strong>
                  </p>
                  <ul className="text-lg text-blue-200 ml-6 space-y-2">
                    <li>• Las columnas marcadas en <span className="text-emerald-400 font-bold">verde</span> son obligatorias</li>
                    <li>• Las columnas marcadas en <span className="text-purple-400 font-bold">morado</span> son opcionales</li>
                    <li>• Para cada movimiento, llena <strong>Cargo</strong> (si es salida) o <strong>Abono</strong> (si es entrada), nunca ambos</li>
                    <li>• El saldo se calcula automáticamente, no es necesario incluirlo</li>
                  </ul>
              </div>
            </div>
          </div>
        </div>

        <div className="grid gap-4 py-4">
          <div className="grid gap-2">
            <Label htmlFor="file" className="text-3xl font-bold text-white">Seleccionar Archivo Excel o CSV</Label>
            <div className="flex items-center gap-4">
              <Input
                id="file"
                type="file"
                accept=".xlsx,.xls,.csv"
                onChange={handleFileUpload}
                disabled={loading}
                className="h-24 text-3xl bg-slate-900/50 border-cyan-500/30 text-white file:text-white file:text-3xl"
              />
              <FileSpreadsheet className="h-16 w-16 text-cyan-400" />
            </div>
          </div>

          {movimientos.length > 0 && (
            <div className="space-y-4">
              <div className="flex gap-6 text-2xl">
                <div className="flex items-center gap-3">
                  <div className="w-5 h-5 bg-emerald-500 rounded-full"></div>
                  <span className="text-white font-bold">Válidos: {movimientosValidos}</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-5 h-5 bg-red-500 rounded-full"></div>
                  <span className="text-white font-bold">Con errores: {movimientosConError}</span>
                </div>
              </div>

              <div className="border border-cyan-500/30 rounded-lg overflow-auto max-h-96 bg-slate-900/50">
                <Table>
                  <TableHeader>
                    <TableRow className="border-b border-cyan-500/30">
                      <TableHead className="w-12 text-xl text-white"></TableHead>
                      <TableHead className="text-xl text-white font-bold">Fecha</TableHead>
                      <TableHead className="text-xl text-white font-bold">No Cheque</TableHead>
                      <TableHead className="text-xl text-white font-bold">Categoría</TableHead>
                      <TableHead className="text-xl text-white font-bold">Descripción</TableHead>
                      <TableHead className="text-xl text-white font-bold text-right">Abono</TableHead>
                      <TableHead className="text-xl text-white font-bold text-right">Cargo</TableHead>
                      <TableHead className="text-xl text-white font-bold">Error</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {movimientos.map((mov, index) => (
                      <TableRow key={index} className={`border-b border-slate-700/50 ${mov.error ? 'bg-red-950/30' : ''}`}>
                        <TableCell>
                          {mov.error ? (
                            <AlertCircle className="h-6 w-6 text-red-400" />
                          ) : (
                            <div className="w-5 h-5 bg-emerald-500 rounded-full"></div>
                          )}
                        </TableCell>
                        <TableCell className="text-lg text-white">{mov.fecha}</TableCell>
                        <TableCell className="text-lg text-cyan-300">{mov.referencia || '-'}</TableCell>
                        <TableCell className="text-lg text-purple-300">
                          {mov.categoriaId ? categorias.find(c => c.id === mov.categoriaId)?.nombre : '-'}
                        </TableCell>
                        <TableCell className="text-lg text-gray-300 max-w-xs truncate">{mov.descripcion}</TableCell>
                        <TableCell className="text-lg text-emerald-400 font-bold text-right">
                          {mov.tipo === 'ingreso' ? formatMoney(mov.monto) : '-'}
                        </TableCell>
                        <TableCell className="text-lg text-red-400 font-bold text-right">
                          {mov.tipo === 'egreso' ? formatMoney(mov.monto) : '-'}
                        </TableCell>
                        <TableCell className="text-lg text-red-400 font-bold">{mov.error || ''}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
          )}
        </div>

        <DialogFooter className="gap-4">
          <Button
            type="button"
            onClick={onClose}
            disabled={loading}
            className="h-16 px-10 text-2xl border-2 border-slate-500/50 bg-transparent text-white hover:bg-slate-800 hover:border-slate-400 font-bold"
          >
            Cancelar
          </Button>
          <Button
            onClick={handleImportar}
            disabled={loading || movimientosValidos === 0}
            className="h-16 px-10 text-2xl bg-gradient-to-r from-emerald-600 via-green-600 to-emerald-700 hover:from-emerald-500 hover:via-green-500 hover:to-emerald-600 text-white shadow-2xl shadow-emerald-500/30 disabled:opacity-50"
          >
            {loading ? 'Importando...' : `Importar ${movimientosValidos} movimientos`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
