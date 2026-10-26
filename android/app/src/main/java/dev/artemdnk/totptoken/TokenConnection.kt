package dev.artemdnk.totptoken

import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException

const val ESPRESSIF_VID = 0x303A

/** Ошибка, которую вернул токен строкой "ERR ...". */
class TokenException(val code: String) : Exception(code) {
    fun localized(): String = when {
        code == "wrong pin" -> "Неверный PIN"
        code == "auth required" -> "Нужно ввести PIN"
        code == "storage full" -> "Память токена заполнена (16 аккаунтов)"
        code == "bad secret" -> "Неверный секрет (ожидается Base32)"
        code.startsWith("too many attempts") -> "Слишком много неверных PIN — токен стёрт"
        code == "selftest failed" -> "Самотест НЕ пройден"
        code == "bad index" -> "Неверный номер аккаунта"
        else -> "Ошибка токена: $code"
    }
}

/**
 * Минимальный драйвер USB CDC-ACM поверх Android USB Host API.
 * ESP32-C6 (USB Serial/JTAG и TinyUSB CDC) отдаёт стандартный CDC-интерфейс,
 * поэтому сторонние библиотеки не нужны.
 */
class UsbCdcPort(manager: UsbManager, device: UsbDevice) : Closeable {
    private val connection: UsbDeviceConnection
    private val dataInterface: UsbInterface
    private val commInterface: UsbInterface?
    private val epIn: UsbEndpoint
    private val epOut: UsbEndpoint

    init {
        var data: UsbInterface? = null
        var comm: UsbInterface? = null
        for (i in 0 until device.interfaceCount) {
            val itf = device.getInterface(i)
            when (itf.interfaceClass) {
                UsbConstants.USB_CLASS_CDC_DATA -> if (data == null) data = itf
                UsbConstants.USB_CLASS_COMM -> if (comm == null) comm = itf
            }
        }
        dataInterface = data ?: throw IOException("У устройства нет последовательного порта")
        commInterface = comm

        var inEp: UsbEndpoint? = null
        var outEp: UsbEndpoint? = null
        for (i in 0 until dataInterface.endpointCount) {
            val ep = dataInterface.getEndpoint(i)
            if (ep.type != UsbConstants.USB_ENDPOINT_XFER_BULK) continue
            if (ep.direction == UsbConstants.USB_DIR_IN) inEp = ep else outEp = ep
        }
        epIn = inEp ?: throw IOException("Не найден входной endpoint")
        epOut = outEp ?: throw IOException("Не найден выходной endpoint")

        connection = manager.openDevice(device) ?: throw IOException("Не удалось открыть USB-устройство")
        commInterface?.let { connection.claimInterface(it, true) }
        if (!connection.claimInterface(dataInterface, true)) {
            connection.close()
            throw IOException("Порт занят другим приложением")
        }

        val ifNum = commInterface?.id ?: 0
        // SET_LINE_CODING: 115200 8N1 (для USB CDC скорость формальная)
        val lineCoding = byteArrayOf(0x00, 0xC2.toByte(), 0x01, 0x00, 0x00, 0x00, 0x08)
        connection.controlTransfer(0x21, 0x20, 0, ifNum, lineCoding, lineCoding.size, 1000)
        // SET_CONTROL_LINE_STATE: DTR=1, RTS=1 одним запросом.
        // Комбинация RTS=1/DTR=0 у ESP32 означает сброс, поэтому ставим обе линии сразу.
        connection.controlTransfer(0x21, 0x22, 0x03, ifNum, null, 0, 1000)
    }

    fun write(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            val n = connection.bulkTransfer(epOut, data, offset, data.size - offset, 2000)
            if (n <= 0) throw IOException("Токен не принимает данные (отключён?)")
            offset += n
        }
    }

    /** Возвращает число прочитанных байт, 0 или отрицательное — по таймауту. */
    fun read(buffer: ByteArray, timeoutMs: Int): Int =
        connection.bulkTransfer(epIn, buffer, buffer.size, timeoutMs)

    override fun close() {
        runCatching { connection.releaseInterface(dataInterface) }
        commInterface?.let { runCatching { connection.releaseInterface(it) } }
        connection.close()
    }
}

/** Текстовый протокол прошивки: команда строкой, ответ заканчивается "OK" или "ERR ...". */
class TokenClient(private val port: UsbCdcPort) {
    private val pending = ByteArrayOutputStream()
    private val chunk = ByteArray(512)

    @Synchronized
    fun command(line: String, timeoutMs: Long = 9000): List<String> {
        port.write((line + "\n").toByteArray(Charsets.UTF_8))
        val out = mutableListOf<String>()
        while (true) {
            val s = readLine(timeoutMs)
            when {
                s == "OK" -> return out
                s.startsWith("ERR") -> throw TokenException(s.removePrefix("ERR").trim())
                else -> out += s
            }
        }
    }

    /** Ждёт, пока прошивка начнёт отвечать (токен мог только что загрузиться). */
    @Synchronized
    fun waitReady() {
        repeat(6) {
            try {
                port.write("\n".toByteArray())
                discard(200)
                command("info", 1500)
                discard(100)
                return
            } catch (_: IOException) {
                // ещё не готов — пробуем снова
            }
        }
        throw IOException("Токен не отвечает. Переподключите кабель.")
    }

    private fun discard(ms: Int) {
        val deadline = System.currentTimeMillis() + ms
        while (System.currentTimeMillis() < deadline) port.read(chunk, 50)
        pending.reset()
    }

    private fun readLine(timeoutMs: Long): String {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (true) {
            val bytes = pending.toByteArray()
            val nl = bytes.indexOf('\n'.code.toByte())
            if (nl >= 0) {
                pending.reset()
                pending.write(bytes, nl + 1, bytes.size - nl - 1)
                return String(bytes, 0, nl, Charsets.UTF_8).trimEnd('\r')
            }
            val left = deadline - System.currentTimeMillis()
            if (left <= 0) throw IOException("Нет ответа от токена")
            val n = port.read(chunk, minOf(left, 200L).toInt())
            if (n > 0) pending.write(chunk, 0, n)
        }
    }
}
