import crypto from 'node:crypto';

/**
 * Utilidad para firmar URLs usando HMAC-SHA256
 * 
 * CONCEPTO CLAVE: Codificar vs Firmar
 * ====================================
 * 
 * CODIFICAR (Base64/Base64Url):
 * - Solo cambia el formato de los datos
 * - NO proporciona seguridad
 * - Cualquiera puede decodificarlo
 * - Ejemplo: "Hola Mundo" -> "SG9sYSBNdW5kbw=="
 * 
 * FIRMAR (HMAC):
 * - Verifica la AUTENTICIDAD e INTEGRIDAD
 * - Requiere una llave secreta compartida
 * - Sin la llave, NO puedes generar una firma válida
 * - Ejemplo: "Hola Mundo" + llave secreta -> hash único
 * 
 * En este proyecto:
 * 1. Codificamos el payload en Base64Url para que sea amigable con URLs
 * 2. Firmamos ese payload con HMAC para que no pueda ser modificado
 */

if (!process.env.SECRET_KEY) {
  throw new Error('SECRET_KEY no está definida. Por favor, establece la variable de entorno SECRET_KEY.');
}

const SECRET_KEY = process.env.SECRET_KEY;

/**
 * Normaliza direcciones IP para manejar variantes de localhost
 * 
 * En desarrollo local, Node.js puede devolver diferentes representaciones de localhost:
 * - IPv4: 127.0.0.1
 * - IPv6-mapped-IPv4: ::ffff:127.0.0.1
 * - IPv6 puro: ::1
 * 
 * Esta función normaliza todas las variantes de localhost a "127.0.0.1"
 * para evitar problemas de coincidencia de IP en desarrollo local.
 * En producción con Docker/Dokploy, las IPs se normalizan automáticamente.
 * 
 * @param {string} ip - Dirección IP a normalizar
 * @returns {string} IP normalizada
 */
function normalizeIp(ip) {
  if (!ip) return ip;

  if (ip === '::1' || ip === '::ffff:127.0.0.1' || ip === '127.0.0.1') {
    return '127.0.0.1';
  }

  if (ip.startsWith('::ffff:')) {
    return ip.replace('::ffff:', '');
  }

  return ip;
}

/**
 * Codifica un objeto JSON a Base64Url
 * Base64Url es una variante de Base64 segura para URLs:
 * - Reemplaza '+' por '-'
 * - Reemplaza '/' por '_'
 * - Elimina el relleno '='
 */
function encodeBase64Url(data) {
  const jsonString = JSON.stringify(data);
  const base64 = Buffer.from(jsonString).toString('base64');
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Decodifica de Base64Url a objeto JSON
 * Es la operación inversa de encodeBase64Url()
 */
function decodeBase64Url(base64Url) {
  const base64 = base64Url
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  const jsonString = Buffer.from(base64, 'base64').toString('utf-8');
  return JSON.parse(jsonString);
}

/**
 * Genera una firma HMAC-SHA256 para un payload
 * 
 * HMAC = Hash-based Message Authentication Code
 * Es un hash que requiere una llave secreta para generar
 * y verificar. La misma llave debe ser usada en ambos lados.
 */
function generateHmacSignature(payload) {
  const hmac = crypto.createHmac('sha256', SECRET_KEY);
  hmac.update(payload);
  const signature = hmac.digest('hex');
  return signature;
}

/**
 * Genera una URL firmada protegida con 3 filtros:
 * 1. UID: Identificador único del usuario
 * 2. IP: Dirección IP del usuario que solicita la firma
 * 3. Expires: Timestamp UNIX de expiración
 * 
 * @param {string} uid - ID único del usuario
 * @param {string} ip - Dirección IP del usuario
 * @param {number} expiresIn - Segundos de vigencia de la firma
 * @returns {object} Objeto con payload codificado y firma
 */
export function signUrl(uid, ip, expiresIn = 3600) {
  const now = Math.floor(Date.now() / 1000);
  const expires = now + expiresIn;

  const normalizedIp = normalizeIp(ip);

  const payload = {
    uid,
    ip: normalizedIp,
    expires
  };

  const encodedPayload = encodeBase64Url(payload);
  const signature = generateHmacSignature(encodedPayload);

  return {
    payload: encodedPayload,
    signature,
    expiresAt: new Date(expires * 1000).toISOString()
  };
}

/**
 * Verifica si una firma HMAC es válida
 * 
 * IMPORTANTE: Usamos crypto.timingSafeEqual para evitar
 * ataques de canal lateral (Timing Attacks).
 * 
 * Timing Attack: Un atacante puede medir cuánto tiempo
 * tarda la comparación para adivinar la firma correcta byte por byte.
 * timingSafeEqual garantiza que la comparación siempre toma el mismo
 * tiempo, sin importar qué tan diferentes sean los valores.
 */
export function verifySignature(payload, receivedSignature) {
  const expectedSignature = generateHmacSignature(payload);

  try {
    crypto.timingSafeEqual(
      Buffer.from(expectedSignature),
      Buffer.from(receivedSignature)
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * Decodifica y valida un payload firmado
 * Verifica los 3 filtros de seguridad:
 * 1. Firma HMAC válida
 * 2. IP del payload coincide con la IP actual
 * 3. El timestamp no ha expirado
 * 
 * @param {string} encodedPayload - Payload codificado en Base64Url
 * @param {string} signature - Firma HMAC a verificar
 * @param {string} currentIp - IP actual del usuario
 * @returns {object} Objeto con { valid, decoded, error }
 */
export function validateSignedUrl(encodedPayload, signature, currentIp) {
  try {
    const isValidSignature = verifySignature(encodedPayload, signature);

    if (!isValidSignature) {
      return {
        valid: false,
        decoded: null,
        error: 'Firma inválida'
      };
    }

    const decoded = decodeBase64Url(encodedPayload);
    const normalizedCurrentIp = normalizeIp(currentIp);

    const now = Math.floor(Date.now() / 1000);

    if (decoded.expires < now) {
      return {
        valid: false,
        decoded,
        error: 'URL expirada'
      };
    }

    if (decoded.ip !== normalizedCurrentIp) {
      return {
        valid: false,
        decoded,
        error: `IP no coincide (esperada: ${decoded.ip}, actual: ${currentIp}${currentIp !== normalizedCurrentIp ? ` [normalizada: ${normalizedCurrentIp}]` : ''})`
      };
    }

    return {
      valid: true,
      decoded,
      error: null
    };

  } catch (error) {
    return {
      valid: false,
      decoded: null,
      error: 'Error al decodificar payload'
    };
  }
}
