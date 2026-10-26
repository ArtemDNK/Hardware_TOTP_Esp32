package dev.artemdnk.totptoken

import android.app.Application
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.util.TimeZone

data class TokenAccount(val index: Int, val name: String, val digits: Int, val period: Int, val algo: String)

data class UiState(
    val connected: Boolean = false,
    val busy: Boolean = false,
    val info: Map<String, String> = emptyMap(),
    val accounts: List<TokenAccount> = emptyList(),
    val timeDrift: Long? = null,
) {
    val authed get() = info["auth"] == "1"
    val pinSet get() = info["pin"] == "1"
    val pinFails get() = info["fails"]?.toIntOrNull() ?: 0
}

class TokenViewModel(app: Application) : AndroidViewModel(app) {
    private val usb = app.getSystemService(UsbManager::class.java)
    private var port: UsbCdcPort? = null
    private var client: TokenClient? = null

    var state by mutableStateOf(UiState())
        private set

    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 8)
    val messages = _messages.asSharedFlow()

    fun findDevice(): UsbDevice? = usb.deviceList.values.firstOrNull { it.vendorId == ESPRESSIF_VID }

    private fun say(text: String) {
        _messages.tryEmit(text)
    }

    fun showMessage(text: String) = say(text)

    private suspend fun cmd(line: String): List<String> = withContext(Dispatchers.IO) {
        (client ?: throw IOException("Токен не подключён")).command(line)
    }

    private fun exec(block: suspend () -> Unit) {
        if (state.busy) return
        viewModelScope.launch {
            state = state.copy(busy = true)
            try {
                block()
            } catch (e: TokenException) {
                say(e.localized())
                runCatching { refreshNow() }
            } catch (e: IOException) {
                closePort()
                state = UiState()
                say(e.message ?: "Ошибка связи с токеном")
            } catch (e: IllegalArgumentException) {
                say(e.message ?: "Ошибка")
            } finally {
                state = state.copy(busy = false)
            }
        }
    }

    // ------------------------------------------------------------ подключение

    fun connect(device: UsbDevice) {
        if (client != null || state.busy) return
        exec {
            withContext(Dispatchers.IO) {
                val p = UsbCdcPort(usb, device)
                try {
                    val c = TokenClient(p)
                    c.waitReady()
                    port = p
                    client = c
                } catch (e: IOException) {
                    p.close()
                    throw e
                }
            }
            refreshNow()
            say("Токен подключён")
        }
    }

    fun disconnect() {
        closePort()
        state = UiState()
    }

    fun onDetached() {
        if (client != null) {
            disconnect()
            say("Токен отключён")
        }
    }

    private fun closePort() {
        runCatching { port?.close() }
        port = null
        client = null
    }

    override fun onCleared() {
        closePort()
    }

    // ------------------------------------------------------------ команды

    private suspend fun refreshNow() {
        val info = parseInfo(cmd("info"))
        val drift = info["time"]?.toLongOrNull()?.let { it - System.currentTimeMillis() / 1000 }
        val accounts = if (info["auth"] == "1") cmd("list").mapNotNull(::parseAccount) else emptyList()
        state = state.copy(connected = true, info = info, accounts = accounts, timeDrift = drift)
    }

    fun refresh() = exec { refreshNow() }

    fun auth(pin: String) = exec {
        cmd("auth $pin")
        refreshNow()
    }

    fun syncTime() = exec {
        // отправляем ровно на границе секунды
        delay(1000 - System.currentTimeMillis() % 1000)
        cmd("time ${(System.currentTimeMillis() + 500) / 1000}")
        val tzMinutes = TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 60000
        cmd("tz $tzMinutes")
        refreshNow()
        say("Время и часовой пояс синхронизированы")
    }

    fun addFromText(text: String) = exec {
        addAll(OtpUri.parse(text))
    }

    fun addManual(account: OtpAccount) = exec {
        addAll(listOf(account))
    }

    private suspend fun addAll(list: List<OtpAccount>) {
        if (list.isEmpty()) throw IllegalArgumentException("В QR-коде нет TOTP-аккаунтов")
        var added = 0
        var lastName = ""
        try {
            for (a in list) {
                val err = OtpUri.validate(a)
                if (err != null) {
                    say("${a.name}: $err")
                    continue
                }
                lastName = OtpUri.deviceName(a.name)
                cmd("add ${Base32.normalize(a.secret)} ${a.digits} ${a.period} ${a.algo} $lastName")
                added++
            }
        } finally {
            if (added > 0) runCatching { refreshNow() }
        }
        say(
            when {
                list.size == 1 && added == 1 -> "Добавлен: $lastName"
                else -> "Добавлено аккаунтов: $added из ${list.size}"
            }
        )
    }

    fun delete(index: Int) = exec {
        cmd("del $index")
        refreshNow()
    }

    fun move(from: Int, to: Int) = exec {
        cmd("move $from $to")
        refreshNow()
    }

    fun setPin(pin: String?) = exec {
        cmd("setpin ${pin ?: "off"}")
        refreshNow()
        say(if (pin == null) "PIN снят" else "PIN установлен")
    }

    fun selfTest() = exec {
        cmd("selftest")
        say("Самотест RFC 6238 пройден")
    }

    fun wipe() = exec {
        cmd("wipe YES")
        refreshNow()
        say("Токен очищен")
    }

    companion object {
        fun parseInfo(lines: List<String>): Map<String, String> =
            lines.filter { '=' in it }.associate { it.substringBefore('=') to it.substringAfter('=') }

        /** Строка "n|имя|цифры|период|алгоритм"; имя может содержать '|' у старых записей. */
        fun parseAccount(line: String): TokenAccount? {
            val p = line.split('|')
            if (p.size < 5) return null
            return TokenAccount(
                index = p[0].toIntOrNull() ?: return null,
                name = p.subList(1, p.size - 3).joinToString("|"),
                digits = p[p.size - 3].toIntOrNull() ?: return null,
                period = p[p.size - 2].toIntOrNull() ?: return null,
                algo = p.last(),
            )
        }
    }
}
