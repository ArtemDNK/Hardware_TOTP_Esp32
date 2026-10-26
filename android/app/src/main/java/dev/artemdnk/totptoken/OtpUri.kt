package dev.artemdnk.totptoken

import java.net.URLDecoder
import java.util.Base64

data class OtpAccount(
    val name: String,
    val secret: String,
    val digits: Int = 6,
    val period: Int = 30,
    val algo: String = "SHA1",
)

object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun encode(data: ByteArray): String {
        val sb = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                sb.append(ALPHABET[(buffer shr (bits - 5)) and 31])
                bits -= 5
            }
            buffer = buffer and ((1 shl bits) - 1)
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (5 - bits)) and 31])
        return sb.toString()
    }

    /** Нормализует секрет: убирает пробелы, дефисы и '=', приводит к верхнему регистру. */
    fun normalize(s: String): String = s.uppercase().filter { it != ' ' && it != '-' && it != '=' }

    /** Длина ключа в байтах или null, если строка не Base32. */
    fun decodedLength(s: String): Int? {
        val c = normalize(s)
        if (c.isEmpty() || c.any { it !in ALPHABET }) return null
        return c.length * 5 / 8
    }
}

object OtpUri {
    val ALGOS = listOf("SHA1", "SHA256", "SHA512")

    fun parse(text: String): List<OtpAccount> {
        val t = text.trim()
        return when {
            t.startsWith("otpauth-migration://", ignoreCase = true) -> parseMigration(t)
            t.startsWith("otpauth://", ignoreCase = true) -> listOf(parseOtpauth(t))
            else -> throw IllegalArgumentException("Это не ссылка 2FA: ожидается otpauth:// или otpauth-migration://")
        }
    }

    /** Ошибка валидации или null, если аккаунт можно записать в токен. */
    fun validate(a: OtpAccount): String? {
        val len = Base32.decodedLength(a.secret) ?: return "секрет не в формате Base32"
        if (len !in 1..64) return "секрет длиннее 64 байт"
        if (a.digits !in 6..8) return "поддерживается 6–8 цифр"
        if (a.period !in 10..255) return "период должен быть 10–255 с"
        if (a.algo !in ALGOS) return "алгоритм ${a.algo} не поддерживается"
        return null
    }

    /** Имя для прошивки: одна строка, не длиннее 31 байта UTF-8, без обрезки посреди символа. */
    fun deviceName(name: String): String {
        var s = name.replace(Regex("[\\r\\n|]"), " ").trim()
        while (s.toByteArray(Charsets.UTF_8).size > 31) {
            s = s.substring(0, s.offsetByCodePoints(0, s.codePointCount(0, s.length) - 1))
        }
        return s.trim().ifEmpty { "Аккаунт" }
    }

    // URLDecoder превращает '+' в пробел, а в Base64 это значимый символ
    private fun pct(s: String): String = URLDecoder.decode(s.replace("+", "%2B"), "UTF-8")

    private fun rawQuery(uri: String): Map<String, String> =
        uri.substringAfter('?', "").split('&').filter { it.isNotEmpty() }.associate {
            pct(it.substringBefore('=')).lowercase() to it.substringAfter('=', "")
        }

    fun parseOtpauth(uri: String): OtpAccount {
        val rest = uri.substringAfter("://")
        if (!rest.substringBefore('/').equals("totp", ignoreCase = true)) {
            throw IllegalArgumentException("Поддерживается только TOTP (не HOTP)")
        }
        val label = pct(rest.substringAfter('/', "").substringBefore('?'))
        // в параметрах otpauth '+' — это закодированный пробел (form-encoding)
        val q = rawQuery(uri).mapValues { URLDecoder.decode(it.value, "UTF-8") }
        val secret = q["secret"]?.let(Base32::normalize)
            ?: throw IllegalArgumentException("В ссылке нет секрета")
        val issuer = q["issuer"].orEmpty()
        val name = if (issuer.isNotEmpty() && !label.startsWith(issuer, ignoreCase = true)) "$issuer:$label" else label
        return OtpAccount(
            name = name.ifBlank { issuer.ifBlank { "Аккаунт" } },
            secret = secret,
            digits = q["digits"]?.toIntOrNull() ?: 6,
            period = q["period"]?.toIntOrNull() ?: 30,
            algo = (q["algorithm"] ?: "SHA1").uppercase(),
        )
    }

    /** Экспорт Google Authenticator ("Перенести аккаунты"): protobuf в base64. */
    fun parseMigration(uri: String): List<OtpAccount> {
        val raw = rawQuery(uri)["data"] ?: throw IllegalArgumentException("В ссылке нет данных экспорта")
        var b64 = pct(raw)
        b64 += "=".repeat((4 - b64.length % 4) % 4)
        val payload = try {
            Base64.getDecoder().decode(b64)
        } catch (_: IllegalArgumentException) {
            Base64.getUrlDecoder().decode(b64)
        }

        val out = mutableListOf<OtpAccount>()
        for ((field, value) in fields(payload)) {
            if (field != 1 || value !is ByteArray) continue
            val p = fields(value).toMap()
            if (((p[6] as? Long) ?: 2L) != 2L) continue          // только TOTP
            val algo = when ((p[4] as? Long) ?: 0L) {
                0L, 1L -> "SHA1"
                2L -> "SHA256"
                3L -> "SHA512"
                else -> continue                                  // MD5 не поддерживается
            }
            val secret = p[1] as? ByteArray ?: continue
            var name = (p[2] as? ByteArray)?.toString(Charsets.UTF_8).orEmpty()
            val issuer = (p[3] as? ByteArray)?.toString(Charsets.UTF_8).orEmpty()
            if (issuer.isNotEmpty() && !name.startsWith(issuer, ignoreCase = true)) name = "$issuer:$name"
            out += OtpAccount(
                name = name.ifBlank { "Аккаунт" },
                secret = Base32.encode(secret),
                digits = if (((p[5] as? Long) ?: 1L) == 2L) 8 else 6,
                period = 30,
                algo = algo,
            )
        }
        return out
    }

    private fun fields(buf: ByteArray): List<Pair<Int, Any>> {
        val result = mutableListOf<Pair<Int, Any>>()
        var i = 0
        fun varint(): Long {
            var shift = 0
            var r = 0L
            while (true) {
                if (i >= buf.size) throw IllegalArgumentException("Повреждённые данные экспорта")
                val b = buf[i++].toInt() and 0xFF
                r = r or ((b and 0x7F).toLong() shl shift)
                if (b and 0x80 == 0) return r
                shift += 7
            }
        }
        while (i < buf.size) {
            val key = varint()
            val field = (key shr 3).toInt()
            when ((key and 7).toInt()) {
                0 -> result += field to varint()
                2 -> {
                    val len = varint().toInt()
                    if (len < 0 || i + len > buf.size) throw IllegalArgumentException("Повреждённые данные экспорта")
                    result += field to buf.copyOfRange(i, i + len)
                    i += len
                }
                1 -> i += 8
                5 -> i += 4
                else -> throw IllegalArgumentException("Повреждённые данные экспорта")
            }
        }
        return result
    }
}
