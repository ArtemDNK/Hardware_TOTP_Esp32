package dev.artemdnk.totptoken

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat

class MainActivity : ComponentActivity() {
    private val vm: TokenViewModel by viewModels()
    private var askedPermission = false

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                ACTION_USB_PERMISSION ->
                    if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) tryConnect(false)
                UsbManager.ACTION_USB_DEVICE_DETACHED -> vm.onDetached()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val filter = IntentFilter().apply {
            addAction(ACTION_USB_PERMISSION)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
        }
        ContextCompat.registerReceiver(this, usbReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)

        setContent {
            val dark = isSystemInDarkTheme()
            val context = LocalContext.current
            val colors = when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
                    if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
                dark -> darkColorScheme()
                else -> lightColorScheme()
            }
            MaterialTheme(colorScheme = colors) {
                TokenScreen(vm = vm, onConnect = { tryConnect(true) })
            }
        }
    }

    override fun onResume() {
        super.onResume()
        tryConnect(false)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.action == UsbManager.ACTION_USB_DEVICE_ATTACHED) {
            askedPermission = false
            tryConnect(false)
        }
    }

    override fun onDestroy() {
        unregisterReceiver(usbReceiver)
        super.onDestroy()
    }

    /** userAction = true — пользователь нажал «Подключить», можно повторно спросить разрешение. */
    private fun tryConnect(userAction: Boolean) {
        val device = vm.findDevice()
        if (device == null) {
            if (userAction) vm.showMessage("Токен не найден. Проверьте кабель и OTG-переходник.")
            return
        }
        val usb = getSystemService(UsbManager::class.java)
        if (usb.hasPermission(device)) {
            vm.connect(device)
        } else if (userAction || !askedPermission) {
            askedPermission = true
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0
            val pi = PendingIntent.getBroadcast(
                this, 0, Intent(ACTION_USB_PERMISSION).setPackage(packageName), flags
            )
            usb.requestPermission(device, pi)
        }
    }

    companion object {
        const val ACTION_USB_PERMISSION = "dev.artemdnk.totptoken.USB_PERMISSION"
    }
}
