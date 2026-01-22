import 'dotenv/config';
import express from 'express';
import { signUrl } from './utils/url-signer.js';
import { requireSignedUrl, logAccess } from './middleware/auth-middleware.js';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use((req, res, next) => {
  console.log(`${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});

app.get('/', (req, res) => {
  res.json({
    message: 'API de URL Signing con HMAC',
    version: '1.0.0',
    endpoints: {
      '/firmar': 'POST - Generar URL firmada',
      '/video/:payload/:signature': 'GET - Acceder a video protegido',
      '/docs': 'GET - Documentación del sistema'
    }
  });
});

app.post('/firmar', (req, res) => {
  const { uid, ip, expiresIn } = req.body;

  if (!uid) {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'Se requiere el campo "uid" (ID de usuario)'
    });
  }

  const clientIp = ip || req.ip;
  const expirationSeconds = expiresIn ? parseInt(expiresIn) : 3600;

  if (isNaN(expirationSeconds) || expirationSeconds <= 0) {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'expiresIn debe ser un número positivo'
    });
  }

  const signedUrl = signUrl(uid, clientIp, expirationSeconds);

  const protectedUrl = `http://localhost:${PORT}/video/${signedUrl.payload}/${signedUrl.signature}`;

  res.json({
    message: 'URL firmada generada exitosamente',
    uid: uid,
    ip: clientIp,
    ipSource: ip ? 'proporcionada en el body' : 'detectada automáticamente',
    expiresIn: expirationSeconds,
    expiresAt: signedUrl.expiresAt,
    payload: signedUrl.payload,
    signature: signedUrl.signature,
    url: protectedUrl,
    nota: 'Esta URL solo funcionará desde la IP especificada y antes de la fecha de expiración'
  });
});

app.get('/video/:payload/:signature', logAccess, requireSignedUrl, (req, res) => {
  const payload = req.signedPayload;

  res.json({
    message: 'Hola Mundo!',
    subtitle: 'Son Momentos ...',
    userData: {
      uid: payload.uid,
      ip: payload.ip,
      expiresAt: new Date(payload.expires * 1000).toISOString()
    }
  });
});

app.get('/docs', (req, res) => {
  res.json({
    title: 'Documentación del Sistema de URL Signing',
    sections: {
      introduccion: {
        titulo: '¿Qué es URL Signing?',
        explicacion: 'URL Signing es una técnica de seguridad que permite generar URLs temporales y protegidas que solo funcionan para un usuario específico, desde una IP específica y durante un tiempo limitado.',
        beneficios: [
          'Protege recursos sin necesidad de base de datos',
          'Las URLs expiran automáticamente',
          'El usuario no puede compartir la URL con otros',
          'Resistente a ataques de replay'
        ]
      },
      componentes: {
        titulo: 'Componentes del Sistema',
        elementos: {
          payload: 'Datos codificados en Base64Url que contienen: uid, ip, expires',
          signature: 'Firma HMAC-SHA256 generada con una llave secreta',
          middleware: 'Valida la firma, la IP y la expiración antes de permitir acceso'
        }
      },
      seguridad: {
        titulo: 'Medidas de Seguridad',
        medidas: {
          hmac: 'HMAC-SHA256 garantiza integridad y autenticidad',
          timingSafeEqual: 'Prevención de ataques de canal lateral (Timing Attacks)',
          trust_proxy: 'Configuración para obtener la IP real en entornos Docker',
          ip_validation: 'La URL solo funciona desde la IP que la solicitó',
          expiration: 'Las URLs expiran automáticamente después del tiempo especificado'
        }
      },
      flujo: {
        titulo: 'Flujo de Autenticación',
        pasos: [
          '1. Cliente envía POST a /firmar con su uid',
          '2. Servidor genera payload con uid, ip, expires',
          '3. Servidor firma el payload con HMAC-SHA256',
          '4. Servidor devuelve la URL firmada',
          '5. Cliente accede al recurso con la URL firmada',
          '6. Middleware valida firma, IP y expiración',
          '7. Si todo es válido, se entrega el recurso protegido'
        ]
      }
    }
  });
});

app.set('trust proxy', true);

const server = app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║       URL Signing con HMAC - Servidor Activo               ║
╠════════════════════════════════════════════════════════════╣
║  Puerto: ${PORT.toString().padEnd(51)} ║
║  Entorno: ${(process.env.NODE_ENV || 'development').padEnd(48)} ║
║  Trust Proxy: Habilitado (para Docker/Dokploy)          ║
╠════════════════════════════════════════════════════════════╣
║  Endpoints disponibles:                                     ║
║  • POST /firmar            - Generar URL firmada          ║
║  • GET  /video/:p/:s       - Acceder a video protegido     ║
║  • GET  /docs              - Documentación                 ║
╠════════════════════════════════════════════════════════════╣
║  Ejemplo de uso:                                          ║
║  curl -X POST http://localhost:${PORT}/firmar \\          ║
║    -H "Content-Type: application/json" \\                  ║
║    -d '{"uid": "usuario123", "expiresIn": 3600}'           ║
╚════════════════════════════════════════════════════════════╝
  `);
});

server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`Error: El puerto ${PORT} ya está en uso.`);
    console.error('Usa otra variable de entorno PORT o cierra el proceso que ocupa el puerto.');
  } else {
    console.error('Error al iniciar el servidor:', error);
  }
});

export default app;
