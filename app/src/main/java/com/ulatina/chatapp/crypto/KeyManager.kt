package com.ulatina.chatapp.crypto

import android.util.Log
import com.ulatina.chatapp.crypto.dto.EncryptedMessageDTO
import com.ulatina.chatapp.crypto.dto.PublicKeyDTO
import org.json.JSONObject
import javax.crypto.SecretKey

class KeyManager(private val username: String) {
    private val TAG = "E2EE"
    private val myKeyPair = CryptoUtils.generateECKeyPair()

    // Mapa: peer -> shared AES key
    private val sharedKeys: MutableMap<String, SecretKey> = mutableMapOf()

    fun myPublicKeyJson(): String {
        val dto = PublicKeyDTO(
            username = username,
            publicKeyB64 = CryptoUtils.publicKeyToBase64(myKeyPair.public)
        )
        return dto.toJson()
    }

    fun peers(): Set<String> = sharedKeys.keys
    fun hasPeers(): Boolean = sharedKeys.isNotEmpty()

    /**
     * Procesa JSON recibido (clave pública o mensaje cifrado)
     * Devuelve Pair<from, plaintext?> (si es mensaje descifrado) o nulls si era clave pública.
     */
    fun handleIncoming(payloadJson: String): Pair<String?, String?> {
        return try {
            val obj = JSONObject(payloadJson)
            when {
                obj.has("publicKeyB64") -> {
                    val peer = obj.getString("username")
                    val pub = CryptoUtils.publicKeyFromBase64(obj.getString("publicKeyB64"))
                    val key = CryptoUtils.deriveSharedKey(myKeyPair.private, pub)
                    sharedKeys[peer] = key
                    Log.i(TAG, "🔐 SharedKey lista con $peer")
                    null to null
                }
                obj.has("cipher") -> {
                    val from = obj.getString("from")
                    val iv = obj.getString("iv")
                    val cipher = obj.getString("cipher")
                    val key = sharedKeys[from]
                    if (key != null) {
                        val plain = CryptoUtils.decryptAesGcm(
                            CryptoUtils.CipherPayload(iv, cipher), key
                        )
                        from to plain
                    } else {
                        Log.w(TAG, "⚠️ No hay shared key con $from")
                        from to null
                    }
                }
                else -> null to null
            }
        } catch (e: Exception) {
            Log.e(TAG, "parse/decrypt error", e)
            null to null
        }
    }

    /** Cifra per-peer y devuelve payloads JSON listos para enviar */
    fun encryptForAll(text: String): List<String> {
        val out = mutableListOf<String>()
        for ((peer, key) in sharedKeys) {
            val c = CryptoUtils.encryptAesGcm(text, key)
            out += EncryptedMessageDTO(
                from = username,
                to = peer,
                iv = c.ivB64,
                cipher = c.cipherB64
            ).toJson()
        }
        return out
    }

    /** Cifra para un peer específico */
    fun encryptFor(peer: String, message: String): String {
        val key = sharedKeys[peer] ?: error("No shared key con $peer")
        val cipher = CryptoUtils.encryptAesGcm(message, key)
        return EncryptedMessageDTO(from = username, to = peer, iv = cipher.ivB64, cipher = cipher.cipherB64).toJson()
    }
}
