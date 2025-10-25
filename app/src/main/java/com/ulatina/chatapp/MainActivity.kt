package com.ulatina.chatapp

import android.annotation.SuppressLint
import android.os.Bundle
import android.util.Log
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import com.ulatina.chatapp.crypto.KeyManager
import com.ulatina.chatapp.signalr.ChatHubConnection
import kotlinx.coroutines.*

class MainActivity : ComponentActivity() {

    // Backend de PRODUCCIÓN (negotiate):
    private val NEGOTIATE_URL =
        "https://programovil.net"

    // Username simple para pruebas (puedes usar uno real):
    private val username: String by lazy { "android-${System.currentTimeMillis()}" }

    // E2EE
    private lateinit var keyManager: KeyManager
    private lateinit var hub: ChatHubConnection

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 1) Inicializa E2EE + SignalR nativo
        keyManager = KeyManager(username)
        hub = ChatHubConnection(NEGOTIATE_URL)

        hub.connect(
            onConnected = {
                // Publica tu clave pública al conectar
                hub.sendJson("SharePublicKey", keyManager.myPublicKeyJson())
                Log.i("E2EE", "🔑 PublicKey enviada por $username")
            },
            onCipherOrKey = { payloadJson ->
                // Aquí llegan claves públicas o mensajes cifrados
                val (from, plain) = keyManager.handleIncoming(payloadJson)
                when {
                    from != null && plain != null -> {
                        Log.i("E2EE", "📥 [$from]: $plain")
                    }
                    from != null && plain == null -> {
                        Log.i("E2EE", "ℹ️ [$from]: mensaje cifrado pero sin shared key todavía.")
                    }
                    else -> {
                        // Era una clave pública; nada que mostrar
                    }
                }
            },
            onPlain = { obj ->
                // Compatibilidad: si el backend o la web envía en claro
                val user = obj.optString("user")
                val msg = obj.optString("message")
                val ts = obj.optString("fechaHoraCostaRica")
                if (user.isNotEmpty() && msg.isNotEmpty())
                    Log.i("SignalR", "💬 (PLAIN) [$ts] $user: $msg")
            }
        )

        // 2) Mantén tu WebView como UI (sin cambios)
        val webUrl = "https://programovil.net"

        setContent {
            var webViewRef by remember { mutableStateOf<WebView?>(null) }

            BackHandler(enabled = (webViewRef?.canGoBack() == true)) {
                webViewRef?.goBack()
            }

            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { ctx ->
                    WebView(ctx).apply {
                        WebView.setWebContentsDebuggingEnabled(true)
                        settings.javaScriptEnabled = true
                        settings.domStorageEnabled = true
                        settings.databaseEnabled = true
                        settings.loadsImagesAutomatically = true
                        settings.mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
                        settings.cacheMode = WebSettings.LOAD_DEFAULT
                        settings.userAgentString = settings.userAgentString + " AndroidWebView"

                        webViewClient = object : WebViewClient() {
                            override fun shouldOverrideUrlLoading(
                                view: WebView?,
                                request: WebResourceRequest?
                            ): Boolean = false
                        }

                        loadUrl(webUrl)
                        webViewRef = this
                    }
                }
            )
        }
    }

    /**
     * Envía el texto de forma cifrada a todos los peers conocidos.
     * - Si no hay peers todavía, hace eco local y (opcional) manda en claro para compatibilidad.
     */
    private fun sendTextE2EE(text: String, fallbackPlainIfNoPeers: Boolean = true) {
        val peers = keyManager.peers()
        if (peers.isEmpty()) {
            Log.i("E2EE", "👤 Sin peers aún. Eco local: $text")
            if (fallbackPlainIfNoPeers) {
                // Compatibilidad con tu método existente SendMessage(user, message)
                hub.sendPlain("SendMessage", username, text)
                Log.i("E2EE", "↩️ Enviado en claro por compatibilidad.")
            }
            return
        }

        // Cifrar per-peer (uno por destinatario)
        val payloads = keyManager.encryptForAll(text)
        for (p in payloads) {
            hub.sendJson("SendCipher", p)
        }
        Log.i("E2EE", "📤 Enviado cifrado a ${peers.size} peer(s).")
    }

    override fun onDestroy() {
        super.onDestroy()
        hub.stop()
    }
}

