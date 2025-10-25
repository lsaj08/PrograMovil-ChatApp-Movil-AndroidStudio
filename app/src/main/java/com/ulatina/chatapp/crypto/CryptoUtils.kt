package com.ulatina.chatapp.crypto

import android.util.Base64
import java.security.*
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object CryptoUtils {
    private const val AES_MODE = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128

    fun generateECKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(256)               // secp256r1
        return kpg.generateKeyPair()
    }

    fun publicKeyToBase64(pub: PublicKey): String =
        Base64.encodeToString(pub.encoded, Base64.NO_WRAP)

    fun publicKeyFromBase64(b64: String): PublicKey {
        val bytes = Base64.decode(b64, Base64.NO_WRAP)
        val spec = X509EncodedKeySpec(bytes)
        return KeyFactory.getInstance("EC").generatePublic(spec)
    }

    fun deriveSharedKey(
        myPrivate: PrivateKey,
        peerPublic: PublicKey,
        salt: ByteArray? = null,
        info: String = "chatapp-ecdh"
    ): SecretKey {
        val ka = javax.crypto.KeyAgreement.getInstance("ECDH")
        ka.init(myPrivate)
        ka.doPhase(peerPublic, true)
        val shared = ka.generateSecret()
        val prk = hmacSha256(salt ?: ByteArray(32) { 0 }, shared)          // HKDF-extract
        val okm = hmacSha256(prk, (info.toByteArray() + 0x01))             // HKDF-expand (1 bloque)
        return SecretKeySpec(okm.copyOf(32), "AES")
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    data class CipherPayload(val ivB64: String, val cipherB64: String) {
        fun toJson(): String = "{\"iv\":\"$ivB64\",\"cipher\":\"$cipherB64\"}"
    }

    fun encryptAesGcm(plain: String, key: SecretKey): CipherPayload {
        val iv = kotlin.random.Random.Default.nextBytes(12)
        val c = Cipher.getInstance(AES_MODE)
        c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val out = c.doFinal(plain.toByteArray(Charsets.UTF_8))
        return CipherPayload(
            ivB64 = Base64.encodeToString(iv, Base64.NO_WRAP),
            cipherB64 = Base64.encodeToString(out, Base64.NO_WRAP)
        )
    }

    fun decryptAesGcm(payload: CipherPayload, key: SecretKey): String {
        val iv = Base64.decode(payload.ivB64, Base64.NO_WRAP)
        val ct = Base64.decode(payload.cipherB64, Base64.NO_WRAP)
        val c = Cipher.getInstance(AES_MODE)
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val pt = c.doFinal(ct)
        return String(pt, Charsets.UTF_8)
    }
}
