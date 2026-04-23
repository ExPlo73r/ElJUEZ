# ElJuezPY

Herramienta de línea de comandos para consultar la reputación de IOCs (IPs, dominios, hashes y URLs) contra múltiples fuentes de inteligencia de amenazas gratuitas.

## Fuentes consultadas

| Fuente | Tipos de IOC | API key requerida |
|---|---|---|
| VirusTotal | IP, dominio, hash, URL | Sí |
| AbuseIPDB | IP | Sí |
| AlienVault OTX | IP, dominio, hash, URL | Sí (opcional) |
| URLhaus | URL, dominio | No |
| MalwareBazaar | MD5, SHA1, SHA256 | No |
| ThreatFox | IP, dominio, hash, URL | No |

## Requisitos

- Python 3.10+
- Las dependencias listadas en `requirements.txt`

```bash
pip install -r requirements.txt
```

## Configuración

Edita el archivo `.env` con tus API keys:

```
VIRUSTOTAL_KEY=tu_api_key_aqui
ABUSEIPDB_KEY=tu_api_key_aqui
ALIENVAULT_KEY=tu_api_key_aqui   # opcional
```

Obtén las keys de forma gratuita en:
- VirusTotal: https://www.virustotal.com
- AbuseIPDB: https://www.abuseipdb.com
- AlienVault OTX: https://otx.alienvault.com

## Uso

```bash
python main.py <archivo_iocs> -o <nombre_salida> [opciones]
```

### Argumentos

| Argumento | Descripción |
|---|---|
| `archivo_iocs` | Archivo de texto con un IOC por línea |
| `-o / --output` | Nombre base para los archivos de salida |
| `--apis` | APIs a usar (por defecto todas) |
| `--format` | Formatos de salida: `csv`, `json`, `txt` (por defecto los tres) |
| `--no-banner` | Omitir el banner de inicio |

### Ejemplos

```bash
# Consultar todos los IOCs contra todas las APIs
python main.py iocs.txt -o reporte_2024

# Usar solo VirusTotal y AbuseIPDB
python main.py iocs.txt -o reporte --apis virustotal abuseipdb

# Exportar solo en JSON
python main.py iocs.txt -o reporte --format json
```

## Formato del archivo de IOCs

Un IOC por línea. Las líneas que empiezan con `#` se ignoran.

```
# Ejemplo
8.8.8.8
evil.example.com
https://malicious.site/payload
44d88612fea8a8f36de82e1278abb02f
```

Tipos detectados automáticamente: `ip`, `domain`, `url`, `md5`, `sha1`, `sha256`.

## Salida

Se generan hasta tres archivos según el formato elegido:

- `<nombre>.csv` — tabla completa con columnas por fuente
- `<nombre>.json` — resultado completo en JSON estructurado
- `<nombre>_malicioso.txt` — lista de IOCs maliciosos
- `<nombre>_sospechoso.txt` — lista de IOCs sospechosos
- `<nombre>_limpio.txt` — lista de IOCs limpios

## Veredictos

| Veredicto | Criterio |
|---|---|
| **MALICIOSO** | Al menos una fuente lo marca como malicioso |
| **SOSPECHOSO** | Alguna fuente arroja señales de riesgo sin confirmación |
| **LIMPIO** | Ninguna fuente reporta actividad maliciosa |
