package com.ulatina.chatapp.signalr

import android.util.Log
import com.microsoft.signalr.HubConnection
import com.microsoft.signalr.HubConnectionBuilder
import io.reactivex.rxjava3.core.Single
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject

class ChatHubConnection(
    private val negotiateUrl: String
) {
    private val TAG = "SignalR"
    private var hub: HubConnection? = null

    /**
     * Conecta y registra handlers:
     *  - onCipherOrKey: recibe payloads String de ReceivePublicKey / ReceiveCipher
     *  - onPlain: recibe mensajes legacy en claro (JSONObject)
     */
    fun connect(
        onConnected: (() -> Unit)? = null,
        onCipherOrKey: (String) -> Unit,
        onPlain: ((JSONObject) -> Unit)? = null
    ) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Log.i(TAG, "🌐 Solicitando negotiate: $negotiateUrl")
                val client = OkHttpClient()
                val req = Request.Builder().url(negotiateUrl).build()
                client.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) {
                        Log.e(TAG, "❌ negotiate HTTP ${resp.code}")
                        return@launch
                    }
                    val body = resp.body?.string().orEmpty()
                    val obj = JSONObject(body)
                    val url = obj.getString("url")
                    val token = obj.getString("accessToken")

                    hub = HubConnectionBuilder.create(url)
                        .withAccessTokenProvider(Single.fromCallable { token })
                        .build()

                    // E2EE: claves públicas y cifrados
                    hub?.on("ReceivePublicKey", { payload: String -> onCipherOrKey(payload) }, String::class.java)
                    hub?.on("ReceiveCipher",    { payload: String -> onCipherOrKey(payload) }, String::class.java)

                    // Legacy plaintext (por compatibilidad con web si aún manda en claro)
                    onPlain?.let {
                        hub?.on("ReceiveMessage", { json: JSONObject -> it(json) }, JSONObject::class.java)
                    }

                    hub?.start()?.blockingAwait()
                    Log.i(TAG, "✅ Conectado a Azure SignalR (canales E2EE listos).")
                    onConnected?.invoke()
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ Error conectando", e)
            }
        }
    }

    /** Enviar JSON (SharePublicKey / SendCipher) */
    fun sendJson(method: String, payloadJson: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                hub?.send(method, payloadJson)
            } catch (e: Exception) {
                Log.e(TAG, "❌ sendJson error", e)
            }
        }
    }

    /** Enviar plaintext (compatibilidad con tu método SendMessage(user, message)) */
    fun sendPlain(method: String, vararg args: Any) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                hub?.send(method, *args)
            } catch (e: Exception) {
                Log.e(TAG, "❌ sendPlain error", e)
            }
        }
    }

    fun stop() { try { hub?.stop() } catch (_: Exception) {} }
}
