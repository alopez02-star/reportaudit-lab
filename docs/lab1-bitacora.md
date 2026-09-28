# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** Antonio López Ros
- **Repositorio:** https://github.com/alopez02-star/reportaudit-lab
- **Sistema operativo y versión de Python usados:** Windows 11 Home + WSL2 con Ubuntu 24.04.5 LTS; Python 3.12.3

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

---

## Parte B — Auditoría manual (antes de usar ninguna herramienta)

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | `buscar_reportes_cliente` (`app/reporte_auditoria.py`) | 41–42 | **Inyección SQL** (SAST): la consulta se construye concatenando `nombre_cliente` dentro del texto SQL, sin parametrizar. | Parámetro `cliente` de `GET /reportes?cliente=…` (`request.args.get("cliente")`, `servicio.py` l. 41) | `cursor.execute(query)` (l. 42) |
| 2 | `convertir_a_pdf` (`app/reporte_auditoria.py`) | 50–51 | **Inyección de comandos del SO** (SAST): el nombre de archivo se concatena en una orden que ejecuta la *shell* con `os.system`; un `;`, `&` o `\|` en el nombre añade órdenes nuevas. El `except ValueError` de `servicio.py` (l. 56) no filtra nada: `convertir_a_pdf` nunca lanza `ValueError`. | Parámetro `archivo` de `GET /convertir?archivo=…` (`request.args.get("archivo")`, `servicio.py` l. 53) | `os.system(comando)` (l. 51) |
| 3 | `cargar_configuracion` (`app/reporte_auditoria.py`) | 33 | **Deserialización YAML insegura** (SAST): `yaml.load` con `Loader=yaml.Loader` (el *Loader* completo) puede construir objetos Python arbitrarios (p. ej. etiquetas `!!python/object/apply:os.system`), es decir, ejecutar código al leer el archivo. | Contenido del archivo YAML leído (`app/config.yaml`, ruta `RUTA_CONFIG` en `servicio.py` l. 22–23) | `yaml.load(f, Loader=yaml.Loader)` (l. 33) |
| 4 | `hash_password_legacy` (`app/reporte_auditoria.py`) | 57 | **Hash criptográfico débil** (SAST): MD5 para contraseñas y **sin sal**; MD5 es rapidísimo de calcular por fuerza bruta y, sin sal, dos contraseñas iguales dan el mismo hash (tablas *rainbow*). | Parámetro `password` de la función (contraseñas de clientes del sistema legado) | `hashlib.md5(password.encode()).hexdigest()` (l. 57) |
| 5 | Constantes del módulo (`app/reporte_auditoria.py`) | 21–22 | **Secretos expuestos** (secreto): `NOTIFICATION_API_KEY` y `SMTP_PASSWORD` están escritas en claro en el código, que ya está en un repositorio **público** y en su historial de Git. Además, `notificar_cliente` (l. 62) imprime el prefijo de la clave en el log. | El propio código fuente / historial de Git (cualquiera que lea el repositorio) | Uso de las credenciales: servicio de notificaciones (l. 62) y servidor SMTP |

**Síntoma observado (Paso C.2):** `GET /reportes?cliente=o'brien_ltd` —un cliente
legítimo que existe en la base de datos— devuelve **500 Internal Server Error**, y
en la terminal del servicio aparece `sqlite3.OperationalError: near "brien_ltd":
syntax error`. El traceback recorre exactamente la ruta *source → sink* de la
sospecha 1: `servicio.py` l. 42 → `reporte_auditoria.py` l. 42 (`cursor.execute`).
El apóstrofo cierra antes de tiempo la cadena SQL y el resto del nombre se
interpreta como parte de la orden: los datos se mezclan con las órdenes.
(Capturas: `11_parteC2_navegador_obrien_500.png` y
`12_parteC2_terminal_operationalerror.png`.)

**Impacto en el negocio:** para cada sospecha, explica en una frase qué
consecuencia tendría para ReportAudit y sus clientes si fuera real (qué datos,
qué sistema o qué credencial quedarían expuestos).

1. **Inyección SQL:** un atacante podría leer los reportes de auditoría de
   **todos** los clientes (p. ej. `' OR '1'='1`), no solo los suyos, rompiendo la
   confidencialidad que es la base del negocio de una empresa de auditoría; hoy
   ya deja sin servicio a clientes legítimos como `o'brien_ltd`.
2. **Inyección de comandos:** ejecución de órdenes arbitrarias en el servidor con
   los permisos del servicio: robo de `reportes.db` y de las credenciales,
   borrado de reportes o uso del servidor como punto de entrada a la red interna.
3. **YAML inseguro:** quien consiga modificar (o hacer cargar) un archivo de
   configuración ejecuta código en el servidor al arrancar el servicio; el mismo
   *Loader* reutilizado con un YAML subido por un usuario sería ejecución remota
   directa.
4. **MD5 sin sal:** si se filtra la tabla de contraseñas del sistema legado, las
   contraseñas de los clientes se recuperan en minutos, y como la gente reutiliza
   contraseñas, el daño se extiende a otras cuentas de esos clientes.
5. **Secretos en el código:** cualquiera que vea el repositorio (público) puede
   usar la API de notificaciones y el correo SMTP en nombre de la empresa:
   *phishing* a los clientes con remitente legítimo, costes y pérdida de
   reputación. Borrar la línea no basta: siguen en el historial; hay que
   **rotarlas**.

---

## Parte F — SonarQube Cloud: organización, proyecto y claves

| Dato | Valor |
|---|---|
| Organization Key (`sonar.organization`) | `alopez02-star` (plan Free) |
| Project Key (`sonar.projectKey`) | `alopez02-star_reportaudit-lab` |
| Definición de código nuevo | *Previous version* |
| Automatic Analysis | **Desactivado** (el análisis lo hará el pipeline de GitHub Actions, Parte G) |

(Capturas: `15_parteF1_organizacion_sonarcloud.png`, `16_parteF3_claves_proyecto.png`,
`17_parteF3_automatic_analysis_off.png`.)

---

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓ (sospecha 1, confirmada con `o'brien_ltd`) | ✗ | ✓ `pythonsecurity:S3649` (l. 42, *Taint Vulnerability*: flujo desde `servicio.py`) |  |  |  | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓ (sospecha 2) | ✗ | ✓ `pythonsecurity:S2076` (l. 51, *Taint Vulnerability*: flujo desde `servicio.py`) |  |  |  | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓ (sospecha 3) | ✗ | ✗ |  |  |  | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓ (sospecha 4) | ✓ `python:S4790` (l. 57, *Security Hotspot*: "Make sure that hashing data is safe here") | ✓ `python:S4790` (l. 57) |  |  |  | n/a |
| H5 Clave de API escrita en el código | ✓ (sospecha 5) | ✗ | ✗ |  |  |  |  |
| H6 Contraseña SMTP escrita en el código | ✓ (sospecha 5) | ✓ `python:S2068` (l. 22, *Security Hotspot*: "'password' detected here, review this potentially hard-coded credential") | ✓ `python:S2068` + `secrets:S7552` (l. 22, "Make sure this SMTP password gets revoked…") |  |  |  |  |

**Parte E (SonarQube for IDE sin conexión) — observación:** en
`app/reporte_auditoria.py` el panel *Problems* muestra solo **2 de los 6**
hallazgos, ambos como *Security Hotspots* (a revisar, no vulnerabilidades
confirmadas): la contraseña SMTP (H6, `S2068`, detectada porque la variable se
llama `SMTP_PASSWORD`) y el MD5 (H4, `S4790`). **No ve** la inyección SQL (H1) ni
la de comandos (H2): son hallazgos de *taint analysis* que siguen el dato desde
`servicio.py` hasta el *sink* en otro archivo y se calculan en el servidor de
SonarQube Cloud. Tampoco marca el `yaml.load` con `Loader=yaml.Loader` (H3):
el juego de reglas genérico sin conexión no lo señala. Tampoco ve la clave de API (H5): el
nombre `NOTIFICATION_API_KEY` no casa con la heurística de `S2068` y la regla de
secretos no reconoce ese formato de clave. Mi auditoría manual encontró los 6.
(Captura: `14_parteE_sonarqube_ide_sin_conexion.png`.)

**Parte F (SonarQube for IDE en Connected Mode) — qué ve ahora el editor que antes no veía:**
tras vincular la carpeta al proyecto `alopez02-star_reportaudit-lab`, el editor pasa de 2 a
**5 hallazgos** en `app/reporte_auditoria.py`, porque ahora usa el perfil del proyecto
(*Sonar way comprehensive*) y descarga los resultados que calcula el servidor:
las dos **inyecciones** (H1 `pythonsecurity:S3649`, H2 `pythonsecurity:S2076`), marcadas
como *Taint Vulnerability* con el recorrido completo (*+9 locations*) desde el
`request.args.get(...)` de `servicio.py` hasta el *sink*, y una regla de **secretos**
(`secrets:S7552`) que reconoce la contraseña SMTP como credencial real y pide rotarla.
Siguen sin aparecer el `yaml.load` inseguro (H3) y la clave de API (H5): ninguna
herramienta de Sonar los señala por ahora. (En el servidor aparece además
`python:S4502`, CSRF desactivado en `servicio.py` l. 25, que no estaba en mi lista.)
(Captura: `22_parteF6_connected_mode_hallazgos.png`.)

**Conclusión de la matriz** (Parte K): ¿alguna herramienta lo detectó todo? ¿Qué
te dice eso sobre depender de una sola herramienta?

---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) |  |
| Componentes Python en el SBOM |  |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen |  |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) |  |

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |  |

**Comparación con Dependabot** (Parte H): ¿las alertas coinciden con Grype? Explica
cualquier diferencia.

**Documento VEX:** copia `plantillas/reportaudit.openvex.json` a
`docs/evidencias/`, rellénalo, enlázalo aquí y resume en una frase la
justificación.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` |  |  |
| Alertas abiertas de CodeQL (Security → Code scanning) |  |  |
| Vulnerabilidades en SonarQube Cloud (rama main) |  |  |
| Security Hotspots por revisar en SonarQube Cloud |  |  |
| Vulnerabilidades de Grype sobre el SBOM |  |  |
| Alertas abiertas de Dependabot |  |  |

---

## Preguntas de comprobación (Sección 7 de la guía)

1.
2.
3.
4.
5.
6.
7.
8.
9.
10.
11.
12.
