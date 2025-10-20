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

      const movimientosImportados: MovimientoImportado[] = await Promise.all(
        jsonData.map(async (row: any) => {
          const tipo = parseTipo(row.Tipo || row.tipo)
          const movimiento: MovimientoImportado = {
            fecha: parseDate(row.Fecha || row.fecha),
            tipo,
            monto: parseFloat(row.Monto || row.monto || 0),
            descripcion: String(row.Descripcion || row.descripcion || ''),
            categoriaId: await findCategoriaId(row.Categoria || row.categoria || '', tipo),
            referencia: String(row.Referencia || row.referencia || ''),
            beneficiario: String(row.Beneficiario || row.beneficiario || ''),
            comentarios: String(row.Comentarios || row.comentarios || ''),
            notas: String(row.Notas || row.notas || ''),
          }

          // Validar
          if (!movimiento.fecha || movimiento.fecha === 'Invalid Date') {
            movimiento.error = 'Fecha inválida'
          } else if (!movimiento.tipo || !['ingreso', 'egreso'].includes(movimiento.tipo)) {
            movimiento.error = 'Tipo debe ser "ingreso" o "egreso"'
          } else if (!movimiento.monto || movimiento.monto <= 0) {
            movimiento.error = 'Monto debe ser mayor a 0'
          } else if (!movimiento.descripcion) {
            movimiento.error = 'Descripción es requerida'
          }

          return movimiento
        })
      )

      setMovimientos(movimientosImportados)
    } catch (error) {
      console.error('Error al leer archivo:', error)
      alert('Error al leer el archivo Excel. Verifica que el formato sea correcto.')
    }
  }

  const parseDate = (value: any): string => {
    if (!value) return ''

    // Si es un número (fecha de Excel)
    if (typeof value === 'number') {
      const date = XLSX.SSF.parse_date_code(value)
      return `${date.y}-${String(date.m).padStart(2, '0')}-${String(date.d).padStart(2, '0')}`
    }

    // Si es string, intentar parsear
    if (typeof value === 'string') {
      const date = new Date(value)
      if (!isNaN(date.getTime())) {
        return date.toISOString().split('T')[0]
      }
    }

    return 'Invalid Date'
  }

  const parseTipo = (value: any): TipoMovimiento => {
    const tipo = String(value || '').toLowerCase().trim()
    if (tipo === 'ingreso' || tipo === 'abono') return 'ingreso'
    if (tipo === 'egreso' || tipo === 'cargo') return 'egreso'
    return 'egreso'
  }

  const findCategoriaId = async (nombre: string, tipo: TipoMovimiento): Promise<string> => {
    if (!nombre || !user) return ''

    // Buscar si ya existe
    const categoria = categorias.find(c =>
      c.nombre.toLowerCase() === nombre.toLowerCase() && c.tipo === tipo
    )

    if (categoria) return categoria.id

    // Si no existe, crearla
    try {
      const newCategoriaId = await createCategoria(user.uid, nombre.trim(), tipo)
      // Recargar categorías para que esté disponible en las siguientes filas
      const updatedCategorias = await getCategorias(user.uid)
      setCategorias(updatedCategorias)
      return newCategoriaId
    } catch (error) {
      console.error('Error al crear categoría automáticamente:', error)
      return ''
    }
  }

  const handleImportar = async () => {
    if (!user) return

    const movimientosValidos = movimientos.filter(m => !m.error)
    if (movimientosValidos.length === 0) {
      alert('No hay movimientos válidos para importar')
      return
    }

    try {
      setLoading(true)

      for (const movimiento of movimientosValidos) {
        await createMovimiento(user.uid, cuentaId, movimiento)
      }

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
      <DialogContent className="max-w-6xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Importar Movimientos desde Excel</DialogTitle>
          <DialogDescription>
            Sube un archivo Excel (.xlsx) con las columnas: Fecha, Tipo, Monto, Descripción, Categoría, Referencia, Beneficiario, Comentarios, Notas
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-4">
          <div className="grid gap-2">
            <Label htmlFor="file">Archivo Excel</Label>
            <div className="flex items-center gap-4">
              <Input
                id="file"
                type="file"
                accept=".xlsx,.xls"
                onChange={handleFileUpload}
                disabled={loading}
              />
              <FileSpreadsheet className="h-8 w-8 text-gray-400" />
            </div>
          </div>

          {movimientos.length > 0 && (
            <div className="space-y-4">
              <div className="flex gap-4 text-sm">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                  <span>Válidos: {movimientosValidos}</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                  <span>Con errores: {movimientosConError}</span>
                </div>
              </div>

              <div className="border rounded-lg overflow-auto max-h-96">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-12"></TableHead>
                      <TableHead>Fecha</TableHead>
                      <TableHead>Tipo</TableHead>
                      <TableHead>Monto</TableHead>
                      <TableHead>Descripción</TableHead>
                      <TableHead>Categoría</TableHead>
                      <TableHead>Error</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {movimientos.map((mov, index) => (
                      <TableRow key={index} className={mov.error ? 'bg-red-50' : ''}>
                        <TableCell>
                          {mov.error ? (
                            <AlertCircle className="h-4 w-4 text-red-500" />
                          ) : (
                            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                          )}
                        </TableCell>
                        <TableCell className="text-sm">{mov.fecha}</TableCell>
                        <TableCell className="text-sm capitalize">{mov.tipo}</TableCell>
                        <TableCell className="text-sm">{formatMoney(mov.monto)}</TableCell>
                        <TableCell className="text-sm max-w-xs truncate">{mov.descripcion}</TableCell>
                        <TableCell className="text-sm text-gray-600">
                          {mov.categoriaId ? categorias.find(c => c.id === mov.categoriaId)?.nombre : '-'}
                        </TableCell>
                        <TableCell className="text-sm text-red-600">{mov.error || ''}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose} disabled={loading}>
            Cancelar
          </Button>
          <Button
            onClick={handleImportar}
            disabled={loading || movimientosValidos === 0}
          >
            {loading ? 'Importando...' : `Importar ${movimientosValidos} movimientos`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
