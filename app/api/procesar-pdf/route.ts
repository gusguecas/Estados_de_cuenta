import { NextRequest, NextResponse } from 'next/server'
import Anthropic from '@anthropic-ai/sdk'
import { promises as fs } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import PDFParser from 'pdf2json'

export const runtime = 'nodejs'
export const maxDuration = 60

export async function POST(request: NextRequest) {
  let tempFilePath: string | null = null

  try {
    const formData = await request.formData()
    const pdfFile = formData.get('pdf') as File
    const empresa = formData.get('empresa') as string || 'Mi Empresa'

    if (!pdfFile) {
      return NextResponse.json(
        { error: 'No se recibió archivo PDF' },
        { status: 400 }
      )
    }

    if (!pdfFile.name.toLowerCase().endsWith('.pdf')) {
      return NextResponse.json(
        { error: 'El archivo debe ser PDF' },
        { status: 400 }
      )
    }

    // Guardar archivo temporal
    const arrayBuffer = await pdfFile.arrayBuffer()
    const buffer = Buffer.from(arrayBuffer)
    tempFilePath = join(tmpdir(), `pdf-${Date.now()}.pdf`)
    await fs.writeFile(tempFilePath, buffer)

    // Extraer texto del PDF con pdf2json
    let textoPdf: string
    try {
      textoPdf = await new Promise((resolve, reject) => {
        const pdfParser = new (PDFParser as any)(null, 1)

        pdfParser.on('pdfParser_dataError', (errData: any) => {
          reject(new Error(errData.parserError))
        })

        pdfParser.on('pdfParser_dataReady', (pdfData: any) => {
          try {
            // Extraer texto de todas las páginas
            let text = ''
            if (pdfData.Pages) {
              for (const page of pdfData.Pages) {
                if (page.Texts) {
                  for (const textItem of page.Texts) {
                    if (textItem.R) {
                      for (const run of textItem.R) {
                        if (run.T) {
                          text += decodeURIComponent(run.T) + ' '
                        }
                      }
                    }
                  }
                  text += '\n'
                }
              }
            }
            resolve(text.trim())
          } catch (error: any) {
            reject(error)
          }
        })

        pdfParser.loadPDF(tempFilePath!)
      })

      if (!textoPdf || textoPdf.length < 100) {
        // Limpiar archivo antes de retornar error
        if (tempFilePath) {
          try {
            await fs.unlink(tempFilePath)
          } catch (e) {}
        }
        return NextResponse.json(
          { error: 'No se pudo extraer texto del PDF o el archivo está vacío' },
          { status: 400 }
        )
      }
    } catch (error: any) {
      console.error('Error extrayendo texto del PDF:', error)
      // Limpiar archivo antes de retornar error
      if (tempFilePath) {
        try {
          await fs.unlink(tempFilePath)
        } catch (e) {}
      }
      return NextResponse.json(
        { error: 'Error al procesar el PDF: ' + error.message },
        { status: 500 }
      )
    }

    // Procesar con Claude AI
    const apiKey = process.env.ANTHROPIC_API_KEY
    if (!apiKey) {
      return NextResponse.json(
        { error: 'API key de Anthropic no configurada en el servidor' },
        { status: 500 }
      )
    }

    const client = new Anthropic({ apiKey })

    const prompt = `Analiza este estado de cuenta bancario y extrae TODA la información en formato JSON.

EMPRESA: ${empresa}

TEXTO DEL ESTADO DE CUENTA:
${textoPdf}

---

Extrae y devuelve SOLO un objeto JSON válido (sin markdown, sin explicaciones) con esta estructura EXACTA:

{
  "banco": "nombre del banco",
  "cuenta": "últimos 4 dígitos de la cuenta (ej: ****1234)",
  "titular": "nombre del titular de la cuenta",
  "periodo_inicio": "YYYY-MM-DD",
  "periodo_fin": "YYYY-MM-DD",
  "saldo_inicial": 0.00,
  "saldo_final": 0.00,
  "total_cargos": 0.00,
  "total_abonos": 0.00,
  "empresa": "${empresa}",
  "transacciones": [
    {
      "fecha": "YYYY-MM-DD",
      "descripcion": "descripción completa",
      "referencia": "número de referencia si existe",
      "cargo": 0.00,
      "abono": 0.00,
      "saldo": 0.00,
      "tipo": "transferencia|pago|nomina|retiro|deposito|servicio|otro"
    }
  ]
}

REGLAS IMPORTANTES:
1. Extrae TODAS las transacciones que encuentres
2. Los montos deben ser números sin comas (ej: 1000.50 no 1,000.50)
3. Las fechas en formato YYYY-MM-DD
4. Si un campo no existe, usa null o "" o 0.00 según corresponda
5. NO incluyas markdown (\`\`\`) ni explicaciones, SOLO el JSON
6. Los cargos son negativos para el balance, abonos son positivos
7. Clasifica cada transacción según su descripción

Devuelve ÚNICAMENTE el JSON, nada más.`

    try {
      const message = await client.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 8000,
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ]
      })

      // Extraer respuesta
      let respuesta = message.content[0].type === 'text' ? message.content[0].text : ''

      // Limpiar respuesta (por si Claude agrega markdown)
      respuesta = respuesta.trim()
      if (respuesta.startsWith('```json')) {
        respuesta = respuesta.slice(7)
      }
      if (respuesta.startsWith('```')) {
        respuesta = respuesta.slice(3)
      }
      if (respuesta.endsWith('```')) {
        respuesta = respuesta.slice(0, -3)
      }
      respuesta = respuesta.trim()

      // Parsear JSON
      const datos = JSON.parse(respuesta)

      // Validar estructura básica
      if (!datos.transacciones) {
        datos.transacciones = []
      }

      // Agregar metadatos
      datos.procesado_con_ia = true
      datos.modelo_ia = 'claude-sonnet-4-20250514'
      datos.num_transacciones = datos.transacciones.length
      datos.archivo_procesado = pdfFile.name
      datos.fecha_procesamiento = new Date().toISOString()

      // Limpiar archivo temporal
      if (tempFilePath) {
        try {
          await fs.unlink(tempFilePath)
        } catch (e) {}
      }

      return NextResponse.json(datos)

    } catch (error: any) {
      console.error('Error con Claude AI:', error)

      // Limpiar archivo temporal
      if (tempFilePath) {
        try {
          await fs.unlink(tempFilePath)
        } catch (e) {}
      }

      if (error.name === 'SyntaxError') {
        return NextResponse.json(
          {
            error: 'La IA no devolvió JSON válido',
            detalle: error.message
          },
          { status: 500 }
        )
      }

      return NextResponse.json(
        {
          error: 'Error al procesar con IA',
          detalle: error.message
        },
        { status: 500 }
      )
    }

  } catch (error: any) {
    console.error('Error general:', error)

    // Limpiar archivo temporal
    if (tempFilePath) {
      try {
        await fs.unlink(tempFilePath)
      } catch (e) {}
    }

    return NextResponse.json(
      {
        error: 'Error al procesar',
        detalle: error.message
      },
      { status: 500 }
    )
  }
}
