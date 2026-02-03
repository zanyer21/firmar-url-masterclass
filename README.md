# URL Signing con HMAC - Proyecto Educativo

Proyecto educativo completo para enseñar el concepto de URL Signing (Firmado de URLs) utilizando HMAC-SHA256 en Node.js.

esto es un text modificado

## Conceptos Fundamentales

### Codificar vs Firmar

| Característica | Codificar (Base64) | Firmar (HMAC) |
|----------------|-------------------|---------------|
| Propósito | Cambiar formato de datos | Verificar autenticidad e integridad |
| Seguridad | No proporciona seguridad | Proporciona seguridad criptográfica |
| Reversible | Sí,任何人 puede decodificar | No, requiere la llave secreta |
| Caso de uso | Transportar datos binarios en texto | Autenticación de mensajes |

### Cómo Funciona el Sistema

```
┌─────────────────┐       1. POST /firmar        ┌──────────────┐
│  Cliente        │ ──────────────────────────▶ │  Servidor    │
│  (IP: 1.2.3.4) │                            │              │
└─────────────────┘                            └──────────────┘
       ▲                                              │
       │                                              │ 2. Genera payload
       │                                              │    { uid, ip, expires }
       │                                              │    Codifica en Base64Url
       │                                              │    Firma con HMAC-SHA256
       │                                              │
       │                                              │
       │  3. URL Firmada                               │
       └──────────────────────────────────────────────│
              /video/PAYLOAD/SIGNATURE               │
                                                      │
┌─────────────────┐  4. GET /video/:p/:s  ┌────────┴───────┐
│  Cliente        │ ───────────────────────▶│  Middleware   │
│  (IP: 1.2.3.4) │                        │  - Verifica   │
└─────────────────┘                        │    firma HMAC │
                                          │  - Compara IP │
                                          │  - Valida exp │
                                          └───────────────┘
                                                │
                                                │ 5. Si válido
                                                ▼
                                          ┌──────────────┐
                                          │  Recurso     │
                                          │  Protegido   │
                                          └──────────────┘
```

## Seguridad Implementada

1. **HMAC-SHA256**: Garantiza que el payload no ha sido modificado
2. **crypto.timingSafeEqual**: Previene ataques de canal lateral (Timing Attacks)
3. **Validación de IP**: La URL solo funciona desde la IP que la solicitó
4. **Normalización de IP**: Convierte variantes de localhost (::1, ::ffff:127.0.0.1, 127.0.0.1) a una sola representación para evitar problemas en desarrollo local
5. **Expiración**: Las URLs expiran automáticamente después del tiempo especificado
6. **Trust Proxy**: Configurado para funcionar detrás de Docker/Nginx/Dokploy

## Normalización de IPs

En desarrollo local, Node.js puede devolver diferentes representaciones de localhost:
- IPv4: `127.0.0.1`
- IPv6-mapped-IPv4: `::ffff:127.0.0.1`
- IPv6 puro: `::1`

El sistema normaliza todas estas variantes a `127.0.0.1` para garantizar que las URLs funcionen correctamente en desarrollo local. En producción con Docker/Dokploy, las IPs se normalizan automáticamente por el proxy inverso.

**Nota importante**: El problema de las variantes de localhost es común en desarrollo local. Si estás probando con `curl` y ves errores de "IP no coincide" con IPs como `::1` o `::ffff:127.0.0.1`, el sistema ya maneja estas variantes automáticamente. Simplemente genera una nueva URL firmada y prueba de nuevo.

## Estructura del Proyecto

```
firmar-url-masterclass/
├── src/
│   ├── utils/
│   │   └── url-signer.js      # Utilidad de firmado de URLs
│   ├── middleware/
│   │   └── auth-middleware.js # Middleware de seguridad
│   └── app.js                 # Aplicación Express principal
├── .env.example               # Plantilla de variables de entorno
├── Dockerfile                 # Imagen Docker multi-stage
├── docker-compose.yml         # Configuración Docker Compose
└── package.json               # Dependencias del proyecto
```

## Instalación y Ejecución Local

### Prerrequisitos
- Node.js v20 o superior

### Pasos

1. Clonar el repositorio
```bash
cd firmar-url-masterclass
```

2. Instalar dependencias
```bash
npm install
```

3. Configurar variables de entorno
```bash
cp .env.example .env
```

4. Editar `.env` y establecer una `SECRET_KEY` segura:
```bash
SECRET_KEY=tu-clave-secreta-muy-larga-y-aleatoria
```

**IMPORTANTE**: La variable de entorno `SECRET_KEY` es **obligatoria**. El servidor no se iniciará si esta variable no está definida. No existe un fallback hardcoded para evitar claves inseguras en producción.

5. Iniciar el servidor
```bash
npm start
```

## Uso del API

### Generar URL Firmada

**Opción 1: Usar la IP detectada automáticamente**

```bash
curl -X POST http://localhost:3000/firmar \
  -H "Content-Type: application/json" \
  -d '{"uid": "usuario123", "expiresIn": 3600}'
```

**Opción 2: Especificar una IP explícitamente**

```bash
curl -X POST http://localhost:3000/firmar \
  -H "Content-Type: application/json" \
  -d '{"uid": "usuario123", "ip": "190.181.151.19", "expiresIn": 3600}'
```

**Nota**: Al especificar una IP explícitamente, la URL solo funcionará cuando se acceda desde esa IP específica. Esto es útil cuando la solicitud se hace desde un servidor intermedio (como un API Gateway) y quieres permitir el acceso desde la IP del usuario final.

**Respuesta:**
```json
{
  "message": "URL firmada generada exitosamente",
  "uid": "usuario123",
  "ip": "127.0.0.1",
  "ipSource": "detectada automáticamente",
  "expiresIn": 3600,
  "expiresAt": "2025-01-22T14:00:00.000Z",
  "payload": "eyJ1aWQiOiJ1c3VhcmlvMTIzIiwiaXAiOiIxMjcuMC4wLjEiLCJleHBpcmVzIjoxNzM3NTYwMDAwfQ",
  "signature": "a1b2c3d4e5f6g7h8i9j0...",
  "url": "http://localhost:3000/video/eyJ1aWQiOiJ1c3VhcmlvMTIzIiwiaXAiOiIxMjcuMC4wLjEiLCJleHBpcmVzIjoxNzM3NTYwMDAwfQ/a1b2c3d4e5f6g7h8i9j0...",
  "nota": "Esta URL solo funcionará desde la IP especificada y antes de la fecha de expiración"
}
```

### Acceder al Recurso Protegido

```bash
curl http://localhost:3000/video/PAYLOAD/SIGNATURE
```

**Respuesta exitosa:**
```json
{
  "message": "Hola Mundo!",
  "subtitle": "Son Momentos ...",
  "userData": {
    "uid": "usuario123",
    "ip": "127.0.0.1",
    "expiresAt": "2025-01-22T14:00:00.000Z"
  }
}
```

**Errores posibles:**

- **Firma inválida** (401):
```json
{
  "error": "Unauthorized",
  "message": "Firma inválida"
}
```

- **URL expirada** (410):
```json
{
  "error": "Gone",
  "message": "URL expirada"
}
```

- **IP no coincide** (403):
```json
{
  "error": "Forbidden",
  "message": "IP no coincide (esperada: 127.0.0.1, actual: 1.2.3.4)"
}
```

## Despliegue con Docker

### Despliegue con Docker Compose

1. Configurar el archivo `.env` con tu `SECRET_KEY`

2. Construir y ejecutar el contenedor:
```bash
docker-compose up -d
```

3. Verificar que el contenedor está corriendo:
```bash
docker-compose ps
```

### Despliegue en Dokploy

1. Subir el código a tu repositorio Git

2. Crear un nuevo proyecto en Dokploy

3. Añadir las variables de entorno:
   - `SECRET_KEY`: Tu llave secreta larga y aleatoria
   - `NODE_ENV`: production
   - `PORT`: 3000

4. Configurar el Docker Compose en Dokploy usando el archivo `docker-compose.yml`

5. Desplegar

El middleware `app.set('trust proxy', true)` garantiza que Express detecte correctamente la IP del usuario detrás del proxy de Dokploy.

## Generación de Clave Secreta Segura

Para generar una clave segura de 64 caracteres (hexadecimal):

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Tecnologías Utilizadas

- **Node.js v20**: Runtime JavaScript
- **Express**: Framework web
- **crypto (Módulo nativo)**: Criptografía
- **Docker**: Contenedores
- **Docker Compose**: Orquestación de contenedores

## Referencias

- [Node.js Crypto Documentation](https://nodejs.org/api/crypto.html)
- [Express Documentation](https://expressjs.com/)
- [HMAC on Wikipedia](https://en.wikipedia.org/wiki/HMAC)

## Licencia

MIT
