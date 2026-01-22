import { validateSignedUrl } from '../utils/url-signer.js';

/**
 * Middleware de seguridad para validar URLs firmadas con HMAC
 * 
 * Este middleware protege rutas específicas verificando que:
 * 1. La URL tiene una firma HMAC válida
 * 2. La IP del usuario coincide con la IP del payload
 * 3. La URL no ha expirado
 * 
 * Si alguna de las validaciones falla, el middleware rechaza la petición
 * con un código de estado HTTP apropiado (401, 403, 410).
 * 
 * Uso:
 * app.get('/video/:payload/:signature', requireSignedUrl, (req, res) => {
 *   res.send('Acceso concedido al recurso protegido');
 * });
 */
export function requireSignedUrl(req, res, next) {
  const { payload, signature } = req.params;
  const clientIp = req.ip;
  
  if (!payload || !signature) {
    return res.status(400).json({
      error: 'URL inválida',
      message: 'Se requieren payload y signature en la URL'
    });
  }
  
  const validation = validateSignedUrl(payload, signature, clientIp);
  
  if (!validation.valid) {
    let statusCode = 401;
    let errorType = 'Unauthorized';
    
    if (validation.error === 'URL expirada') {
      statusCode = 410;
      errorType = 'Gone';
    } else if (validation.error.includes('IP')) {
      statusCode = 403;
      errorType = 'Forbidden';
    }
    
    return res.status(statusCode).json({
      error: errorType,
      message: validation.error,
      debug: process.env.NODE_ENV === 'development' ? {
        payload,
        signature,
        clientIp,
        decoded: validation.decoded
      } : undefined
    });
  }
  
  req.signedPayload = validation.decoded;
  next();
}

/**
 * Middleware para logging de intentos de acceso
 * Útil para detectar patrones sospechosos o ataques
 */
export function logAccess(req, res, next) {
  const { payload, signature } = req.params;
  const timestamp = new Date().toISOString();
  
  console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip}`);
  
  if (process.env.NODE_ENV === 'development') {
    console.log('User-Agent:', req.get('User-Agent'));
  }
  
  next();
}
