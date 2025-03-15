import crypto from 'crypto'

/**
 * Şifreleme için bir anahtar ve IV oluşturur
 * @returns {{key: Buffer, iv: Buffer, keyHex: string, ivHex: string}}
 */
function generateKeys() {
  // 32 byte (256 bit) anahtar ve 12 byte IV oluştur (Python AESGCM ile uyumlu)
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  
  return {
    key,
    iv,
    keyHex: key.toString('hex'),
    ivHex: iv.toString('hex')
  };
}

/**
 * Bir payload'ı şifreler
 * 
 * @param {Object|string} payload - Şifrelenecek veri
 * @param {Buffer|string} key - Şifreleme anahtarı (Buffer veya hex string)
 * @param {Buffer|string} iv - Başlangıç vektörü (Buffer veya hex string)
 * @returns {string} - Şifrelenmiş veri (format: iv:authTag:şifrelenenVeri)
 */
function encryptPayload(payload, key, iv) {
  // String anahtarları Buffer'a çevir
  const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
  const ivBuffer = Buffer.isBuffer(iv) ? iv : Buffer.from(iv, 'hex');
  
  // Payload'ı JSON string'e çevir (eğer object ise)
  const data = typeof payload === 'object' ? JSON.stringify(payload) : payload;
  
  // AES-256-GCM şifreleyici oluştur
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, ivBuffer);
  
  // Veriyi şifrele
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // Doğrulama etiketini al (authentication tag)
  const authTag = cipher.getAuthTag().toString('hex');
  
  // Tüm bilgileri tek bir string olarak geri dön
  // Format: iv:authTag:şifrelenenVeri
  return `${ivBuffer.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Şifrelenmiş bir payload'ı deşifre eder
 * 
 * @param {string} encryptedData - Şifrelenmiş veri (format: iv:authTag:şifrelenenVeri)
 * @param {Buffer|string} key - Şifreleme anahtarı (Buffer veya hex string)
 * @param {boolean} parseJson - Sonucu JSON olarak ayrıştır
 * @returns {Object|string} - Deşifre edilmiş veri
 */
function decryptPayload(encryptedData, key, parseJson = true) {
  // String anahtarları Buffer'a çevir
  const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
  
  // Şifrelenmiş veriyi parçalara ayır
  const [ivHex, authTagHex, encrypted] = encryptedData.split(':');
  
  // Buffer nesnelerini oluştur
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  
  // Deşifreleyici oluştur
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
  decipher.setAuthTag(authTag);
  
  // Veriyi deşifre et
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  // Eğer istenirse JSON olarak ayrıştır
  if (parseJson) {
    try {
      return JSON.parse(decrypted);
    } catch (e) {
      // JSON değilse string olarak geri dön
      return decrypted;
    }
  }
  
  return decrypted;
}

/**
 * Payloadları şifrelemek için Python'un AESGCM ile uyumlu bir API
 */
class PayloadCrypto {
  constructor(key) {
    if (!key) {
      this.key = generateKeys().key;
      console.log("Yeni anahtar oluşturuldu, uzunluk:", this.key.length, "bytes");
    } else if (Buffer.isBuffer(key)) {
      this.key = key;
      console.log("Buffer anahtar kullanılıyor, uzunluk:", this.key.length, "bytes");
    } else if (typeof key === 'string') {
      this.key = Buffer.from(key, 'hex');
      console.log("String anahtar hex'e dönüştürüldü, uzunluk:", this.key.length, "bytes");
    } else {
      throw new Error("Geçersiz anahtar formatı");
    }
    
    // Anahtar uzunluğunu kontrol et
    if (this.key.length !== 16 && this.key.length !== 24 && this.key.length !== 32) {
      throw new Error(`Geçersiz anahtar uzunluğu: ${this.key.length} bytes. 16, 24 veya 32 bytes olmalı.`);
    }
  }
  
  /**
   * Payload şifrele - Python'un AESGCM ile uyumlu
   * @param {Object|string} payload - Şifrelenecek veri
   * @returns {{encrypted: string, iv: string}} - Şifrelenmiş veri ve kullanılan IV
   */
  encrypt(payload) {
    // Python tarafıyla uyumlu olması için 12 byte IV kullan
    const iv = crypto.randomBytes(12);
    
    // Payload'ı uygun formata dönüştür
    const data = typeof payload === 'object' ? JSON.stringify(payload) : payload;
    const dataBuffer = Buffer.from(data, 'utf8');
    
    console.log("Şifreleme bilgileri:");
    console.log("- Anahtar uzunluğu:", this.key.length, "bytes");
    console.log("- IV uzunluğu:", iv.length, "bytes");
    console.log("- Veri uzunluğu:", dataBuffer.length, "bytes");
    
    // AES-GCM şifreleyici oluştur
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    
    // Veriyi şifrele
    const encrypted = Buffer.concat([
      cipher.update(dataBuffer),
      cipher.final()
    ]);
    
    // Doğrulama etiketini al (authentication tag)
    const authTag = cipher.getAuthTag();
    
    console.log("- Şifrelenmiş veri uzunluğu:", encrypted.length, "bytes");
    console.log("- Auth tag uzunluğu:", authTag.length, "bytes");
    
    // Python'un AESGCM ile uyumlu olması için şifrelenmiş veri ve auth tag'i birleştir
    // Python'da AESGCM.encrypt() fonksiyonu şifrelenmiş veri ve auth tag'i birleşik olarak döndürür
    const combinedBuffer = Buffer.concat([encrypted, authTag]);
    console.log("- Toplam uzunluk:", combinedBuffer.length, "bytes");
    
    // Base64 formatına dönüştür
    return {
      encrypted: combinedBuffer.toString('base64'),
      iv: iv.toString('base64')
    };
  }
  
  /**
   * Payload deşifre et - Python'un AESGCM ile uyumlu
   * @param {string} encryptedData - Şifrelenmiş veri (Base64 formatında)
   * @param {string} iv - Başlangıç vektörü (IV) (Base64 formatında)
   * @param {boolean} parseJson - JSON olarak ayrıştır
   * @returns {Object|string} - Deşifre edilmiş veri
   */
  decrypt(encryptedData, iv, parseJson = true) {
    try {
      // Base64 formatındaki veriyi çöz
      const encryptedBuffer = Buffer.from(encryptedData, 'base64');
      const ivBuffer = Buffer.from(iv, 'base64');
      
      console.log("Deşifreleme bilgileri:");
      console.log("- Anahtar uzunluğu:", this.key.length, "bytes");
      console.log("- IV uzunluğu:", ivBuffer.length, "bytes");
      console.log("- Şifrelenmiş veri uzunluğu:", encryptedBuffer.length, "bytes");
      
      // Python'un AESGCM ile uyumlu olması için şifrelenmiş veriden auth tag'i ayır
      // Python'da AESGCM.encrypt() fonksiyonu şifrelenmiş veri ve auth tag'i birleşik olarak döndürür
      const tagLength = 16; // GCM auth tag uzunluğu 16 byte'tır
      
      if (encryptedBuffer.length < tagLength) {
        throw new Error(`Şifrelenmiş veri çok kısa: ${encryptedBuffer.length} bytes. En az ${tagLength} bytes olmalı.`);
      }
      
      // Şifrelenmiş veriden auth tag'i ayır
      const ciphertext = encryptedBuffer.slice(0, encryptedBuffer.length - tagLength);
      const authTag = encryptedBuffer.slice(encryptedBuffer.length - tagLength);
      
      console.log("- Ciphertext uzunluğu:", ciphertext.length, "bytes");
      console.log("- Auth tag uzunluğu:", authTag.length, "bytes");
      
      // AES-GCM deşifreleyici oluştur
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, ivBuffer);
      
      // Auth tag'i ayarla
      decipher.setAuthTag(authTag);
      
      // Veriyi deşifre et
      const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
      ]);
      
      // String'e çevir
      const decryptedText = decrypted.toString('utf8');
      console.log("- Deşifre edilmiş metin:", decryptedText.substring(0, 100) + (decryptedText.length > 100 ? "..." : ""));
      
      // Eğer istenirse JSON olarak ayrıştır
      if (parseJson) {
        try {
          return JSON.parse(decryptedText);
        } catch (e) {
          console.error('JSON ayrıştırma hatası:', e);
          // JSON değilse string olarak geri dön
          return decryptedText;
        }
      }
      
      return decryptedText;
    } catch (error) {
      console.error('Deşifreleme hatası:', error);
      throw new Error('Deşifreleme başarısız oldu: ' + error.message);
    }
  }
}

export {
    generateKeys,
    encryptPayload,
    decryptPayload,
    PayloadCrypto
}
