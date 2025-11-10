import { NextRequest, NextResponse } from 'next/server'
import Anthropic from '@anthropic-ai/sdk'

const SYSTEM_PROMPT = `Eres un asistente experto en extracción de datos de estados de cuenta bancarios.

Tu tarea es analizar el estado de cuenta bancario en PDF y extraer TODA la información de las transacciones de forma PRECISA.

IMPORTANTE:
- Extrae TODAS las transacciones sin omitir ninguna
- CONVIERTE todas las fechas al formato YYYY-MM-DD (por ejemplo: 2024-01-15)
- Separa claramente CARGOS (salidas de dinero) y ABONOS (entradas de dinero)
- Los cargos deben tener monto en el campo "cargo" (positivo) y abono en 0
- Los abonos deben tener monto en el campo "abono" (positivo) y cargo en 0
- Si no hay referencia, usa null

Devuelve la información en formato JSON con esta estructura EXACTA:
{
  "banco": "Nombre del banco",
  "cuenta": "Número de cuenta o últimos 4 dígitos",
  "titular": "Nombre del titular",
  "periodo_inicio": "YYYY-MM-DD",
  "periodo_fin": "YYYY-MM-DD",
  "saldo_inicial": 0.00,
  "saldo_final": 0.00,
  "total_cargos": 0.00,
  "total_abonos": 0.00,
  "empresa": "Nombre de la empresa del contexto",
  "num_transacciones": 0,
  "transacciones": [
    {
      "fecha": "YYYY-MM-DD",
      "descripcion": "Descripción del movimiento",
      "referencia": "Número de referencia o null",
      "cargo": 0.00,
      "abono": 0.00,
      "saldo": 0.00,
      "tipo": "tipo de movimiento (ej: transferencia, pago, depósito, etc)"
    }
  ],
  "procesado_con_ia": true,
  "modelo_ia": "claude-sonnet-4-5"
}`

export async function POST(request: NextRequest) {
  try {
    // Validar API Key
    const apiKey = process.env.ANTHROPIC_API_KEY
    if (!apiKey) {
      return NextResponse.json(
        { error: 'API key de Anthropic no configurada' },
        { status: 500 }
      )
    }

    // Leer form data
    const formData = await request.formData()
    const pdfFile = formData.get('pdf') as File
    const empresa = (formData.get('empresa') as string) || 'Mi Empresa'

    if (!pdfFile) {
      return NextResponse.json(
        { error: 'No se proporcionó archivo PDF' },
        { status: 400 }
      )
    }

    // Convertir PDF a base64
    const bytes = await pdfFile.arrayBuffer()
    const buffer = Buffer.from(bytes)
    const base64PDF = buffer.toString('base64')

    // Inicializar cliente de Anthropic
    const anthropic = new Anthropic({
      apiKey: apiKey
    })

    // Preparar el prompt con contexto de la empresa
    const userPrompt = `Analiza este estado de cuenta bancario para la empresa "${empresa}".

Extrae TODA la información y devuelve el JSON con el formato especificado.

IMPORTANTE:
- Asegúrate de incluir TODAS las transacciones
- El campo "empresa" debe ser: "${empresa}"
- Calcula correctamente los totales de cargos y abonos
- Verifica que el saldo_final coincida con el último saldo de las transacciones`

    // Llamar a Claude para analizar el PDF
    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-5',
      max_tokens: 16000,
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'document',
              source: {
                type: 'base64',
                media_type: 'application/pdf',
                data: base64PDF
              }
            },
            {
              type: 'text',
              text: userPrompt
            }
          ]
        }
      ],
      system: SYSTEM_PROMPT
    })

    // Extraer el texto de la respuesta
    const content = message.content[0]
    if (content.type !== 'text') {
      throw new Error('Respuesta inesperada de Claude')
    }

    let responseText = content.text

    // Limpiar la respuesta para obtener solo el JSON
    // Claude a veces envuelve el JSON en ```json ... ```
    const jsonMatch = responseText.match(/```json\s*([\s\S]*?)\s*```/) ||
                     responseText.match(/```\s*([\s\S]*?)\s*```/)

    if (jsonMatch) {
      responseText = jsonMatch[1]
    }

    // Parsear el JSON
    const resultado = JSON.parse(responseText)

    // Validar que tenga la estructura esperada
    if (!resultado.transacciones || !Array.isArray(resultado.transacciones)) {
      throw new Error('Formato de respuesta inválido')
    }

    return NextResponse.json(resultado)

  } catch (error) {
    console.error('Error al procesar PDF:', error)

    if (error instanceof Error) {
      return NextResponse.json(
        {
          error: 'Error al procesar el PDF',
          detalle: error.message
        },
        { status: 500 }
      )
    }

    return NextResponse.json(
      { error: 'Error desconocido al procesar el PDF' },
      { status: 500 }
    )
  }
}
