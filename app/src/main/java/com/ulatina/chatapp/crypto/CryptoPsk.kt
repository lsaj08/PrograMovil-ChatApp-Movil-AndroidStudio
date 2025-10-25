package com.ulatina.chatapp.crypto

import android.util.Base64
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

object CryptoPsk {
    private const val AES_MODE = "AES/GCM/NoPadding"
    private const val TAG_BITS = 128

    fun deriveKey(passphrase: String, roomId: String, iters: Int = 150_000): SecretKey {
        val salt = MessageDigest.getInstance("SHA-256").digest(("chat:$roomId").toByteArray())
        val spec = PBEKeySpec(passphrase.toCharArray(), salt, iters, 256)
        val f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val raw = f.generateSecret(spec).encoded
        return SecretKeySpec(raw, "AES")
    }

    fun encrypt(key: SecretKey, plain: String, aad: String? = null): Pair<String, String> {
        val iv = Random.Default.nextBytes(12)
        val c = Cipher.getInstance(AES_MODE)
        c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        if (aad != null) c.updateAAD(aad.toByteArray())
        val ct = c.doFinal(plain.toByteArray())
        return Base64.encodeToString(iv, Base64.NO_WRAP) to Base64.encodeToString(ct, Base64.NO_WRAP)
    }

    fun decrypt(key: SecretKey, ivB64: String, ctB64: String, aad: String? = null): String {
        val iv = Base64.decode(ivB64, Base64.NO_WRAP)
        val ct = Base64.decode(ctB64, Base64.NO_WRAP)
        val c = Cipher.getInstance(AES_MODE)
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        if (aad != null) c.updateAAD(aad.toByteArray())
        val pt = c.doFinal(ct)
        return String(pt)
    }
}
