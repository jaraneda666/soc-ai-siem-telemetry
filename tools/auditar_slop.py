#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auditar_slop.py — Auditor de Patrones de Texto IA (Basado en petergyang/no-ai-slop)
Detecta más de 20 patrones típicos de generación de LLM para humanizar textos
y eliminar clichés sin aplanar la voz del redactor.
"""

import sys
import os
import re

PATRONES_SLOP = [
    # 1. Palabras prohibidas explícitas de no-ai-slop adaptadas al español
    (r"\brobust[ao]s?\b|\brobustez\b", "Palabra inflada (robusto/robustez)", "Sustituir por 'alta seguridad', 'estándar AES-256' o término técnico específico."),
    (r"\bfacilit[aóe]n?\b|\bfacilitaron\b", "Verbo genérico de IA (facilitar)", "Usar verbo directo: 'permitió', 'determinó', 'posibilitó' o reformular con sujeto activo."),
    (r"\bapalan(?:car|ca|có|que|cando)\b", "Jerga de IA (apalancar/leverage)", "Sustituir por 'aprovechar', 'utilizar' o verbo concreto."),
    (r"\bempoder(?:ar|a|ó|ando)\b", "Jerga de IA (empoderar/empower)", "Eliminar o sustituir por 'capacitar', 'autorizar'."),
    (r"\bholístic[ao]s?\b", "Adjetivo inflado (holístico)", "Usar 'integral', 'global' o detallar componentes específicos."),
    (r"\bintrincad[ao]s?\b", "Adjetivo cliché (intrincado/intricate)", "Usar 'complejo', 'detallado'."),
    (r"\bmeticulos[ao]s?\b|\bmeticulosamente\b", "Adjetivo inflado (meticuloso/meticulous)", "Usar 'detallado', 'paso a paso', 'metódico'."),

    # 2. Estructura binaria de contraste ("no es X, sino Y" / "no busca X, sino Y")
    (r"\bno\s+[\w\s]{2,40},\s+sino\s+[\w\s]{2,40}\b", "Contraste binario ('no X, sino Y')", "Afirmar Y directamente sin negar X previamente."),

    # 3. Gerundios finales de análisis superficial (, asegurando / , permitiendo / , demostrando)
    (r",\s+(?:garantizando|asegurando|permitiendo|demostrando|destacando|revelando|subrayando)\s+[\w\s]{5,50}\.", "Gerundio conclusivo superficial", "Dividir en dos oraciones o enlazar con sujeto pericial activo."),

    # 4. Cierres enumerativos simétricos tipo bot ("En primer lugar, En segundo lugar, En tercer lugar")
    (r"\bEn\s+primer\s+lugar,\b|\bEn\s+segundo\s+lugar,\b|\bEn\s+tercer\s+lugar,\b", "Simetría robótica en enumeración", "Variar la estructura de los párrafos y vincular con conectores lógicos de causa-efecto."),

    # 5. Revelación con dos puntos teatral ("El detalle clave: ...")
    (r"\b(?:el\s+detalle|lo\s+crucial|la\s+clave|el\s+resultado|lo\s+sorprendente):\s+[a-z]", "Revelación con dos puntos (Colon reveal)", "Integrar como oración natural corrida sin teatralidad."),

    # 6. Aperturas vacías de garganta (Throat-clearing openers)
    (r"\b(?:aquí\s+está\s+el\s+detalle|la\s+verdad\s+es\s+que|lo\s+que\s+nadie\s+te\s+dice|lo\s+cierto\s+es\s+que)\b", "Apertura vacía (Throat-clearing)", "Eliminar la frase y comenzar directamente con el dato técnico."),

    # 7. Adverbios vacíos intensificadores
    (r"\b(?:fundamentalmente|crucialmente|literalmente|inherentemente|inevitablemente)\b", "Adverbio intensificador vacío", "Eliminar el adverbio si no aporta contraste medible.")
]


def auditar_documento(ruta_archivo: str):
    if not os.path.exists(ruta_archivo):
        print(f"[ERROR] No se encuentra el archivo: {ruta_archivo}")
        return

    with open(ruta_archivo, "r", encoding="utf-8") as f:
        lineas = f.readlines()

    hallazgos = []
    for num_linea, linea in enumerate(lineas, 1):
        # Ignorar bloques de código o líneas de metadatos puros
        if linea.strip().startswith("```") or linea.strip().startswith("$") or linea.strip().startswith("C:\\"):
            continue

        for patron, nombre, sugerencia in PATRONES_SLOP:
            for match in re.finditer(patron, linea, re.IGNORECASE):
                hallazgos.append({
                    "linea": num_linea,
                    "patron": nombre,
                    "texto": match.group(0),
                    "contexto": linea.strip(),
                    "sugerencia": sugerencia
                })

    print("=" * 80)
    print("AUDITORÍA DE PATRONES DE IA (FRAMEWORK: petergyang/no-ai-slop)")
    print(f"Archivo analizado: {ruta_archivo}")
    print("=" * 80)

    if not hallazgos:
        print("[OK] No se detectaron patrones de texto IA (no-ai-slop). El texto presenta redacción directa y natural.")
        return 0

    print(f"Se detectaron {len(hallazgos)} patrones de slop a corregir:\n")
    for i, h in enumerate(hallazgos, 1):
        print(f"[{i}] Línea {h['linea']}: {h['patron']}")
        print(f"    Texto detectado: \"{h['texto']}\"")
        print(f"    Contexto: ...{h['contexto'][:90]}...")
        print(f"    Sugerencia: {h['sugerencia']}\n")

    print("-" * 80)
    print(f"Total de patrones detectados: {len(hallazgos)}")
    print("=" * 80)
    return len(hallazgos)


if __name__ == "__main__":
    archivo = sys.argv[1] if len(sys.argv) > 1 else "informe.md"
    auditar_documento(archivo)
