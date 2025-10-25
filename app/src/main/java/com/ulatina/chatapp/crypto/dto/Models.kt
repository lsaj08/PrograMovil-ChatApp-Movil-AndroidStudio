package com.ulatina.chatapp.crypto.dto

data class PublicKeyDTO(
    val username: String,
    val algorithm: String = "EC-P256",
    val publicKeyB64: String
) {
    fun toJson(): String =
        "{\"username\":\"$username\",\"algorithm\":\"$algorithm\",\"publicKeyB64\":\"$publicKeyB64\"}"
}

data class EncryptedMessageDTO(
    val from: String,
    val to: String?,   // null => broadcast; aquí enviaremos per-peer (nombre del receptor)
    val iv: String,
    val cipher: String
) {
    fun toJson(): String =
        "{\"from\":\"$from\",\"to\":${to?.let { "\"$it\"" } ?: "null"},\"iv\":\"$iv\",\"cipher\":\"$cipher\"}"
}
