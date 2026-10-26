package dev.artemdnk.totptoken

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.util.Base64

class OtpUriTest {

    @Test
    fun parsesOtpauth() {
        val a = OtpUri.parse("otpauth://totp/GitHub:artem%40x.ru?secret=jbsw+y3dp-ehpk3pxp&issuer=GitHub&digits=8&algorithm=sha256").single()
        assertEquals("GitHub:artem@x.ru", a.name)
        assertEquals("JBSWY3DPEHPK3PXP", a.secret)
        assertEquals(8, a.digits)
        assertEquals(30, a.period)
        assertEquals("SHA256", a.algo)
        assertNull(OtpUri.validate(a))
    }

    @Test
    fun addsIssuerToLabel() {
        val a = OtpUri.parse("otpauth://totp/artem?secret=JBSWY3DPEHPK3PXP&issuer=Yandex").single()
        assertEquals("Yandex:artem", a.name)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsHotp() {
        OtpUri.parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1")
    }

    @Test
    fun parsesGoogleMigration() {
        fun varint(out: ByteArrayOutputStream, v: Long) {
            var n = v
            while (true) {
                val b = (n and 0x7F).toInt()
                n = n shr 7
                if (n == 0L) { out.write(b); return }
                out.write(b or 0x80)
            }
        }
        fun bytesField(out: ByteArrayOutputStream, f: Int, b: ByteArray) {
            varint(out, (f shl 3 or 2).toLong()); varint(out, b.size.toLong()); out.write(b)
        }
        fun intField(out: ByteArrayOutputStream, f: Int, v: Long) {
            varint(out, (f shl 3).toLong()); varint(out, v)
        }

        val totp = ByteArrayOutputStream().apply {
            bytesField(this, 1, "Hello!Þ­".toByteArray(Charsets.ISO_8859_1))
            bytesField(this, 2, "Почта".toByteArray())
            bytesField(this, 3, "Yandex".toByteArray())
            intField(this, 4, 2); intField(this, 5, 2); intField(this, 6, 2)
        }.toByteArray()
        val hotp = ByteArrayOutputStream().apply {
            bytesField(this, 1, byteArrayOf(1, 2, 3)); bytesField(this, 2, "hotp".toByteArray()); intField(this, 6, 1)
        }.toByteArray()
        val payload = ByteArrayOutputStream().apply {
            bytesField(this, 1, totp); bytesField(this, 1, hotp); intField(this, 2, 1)
        }.toByteArray()

        val data = URLEncoder.encode(Base64.getEncoder().encodeToString(payload), "UTF-8")
        val list = OtpUri.parse("otpauth-migration://offline?data=$data")

        assertEquals(1, list.size)
        val a = list[0]
        assertEquals("Yandex:Почта", a.name)
        assertEquals("JBSWY3DPEHPK3PXP", Base32.encode("Hello!Þ­¾ï".toByteArray(Charsets.ISO_8859_1)))
        assertEquals("JBSWY3DPEHPK2", a.secret)
        assertEquals(8, a.digits)
        assertEquals("SHA256", a.algo)
    }

    @Test
    fun deviceNameFitsFirmware() {
        val n = OtpUri.deviceName("Очень длинное имя аккаунта на кириллице | с чертой")
        assertTrue(n.toByteArray().size <= 31)
        assertTrue('|' !in n)
        assertEquals("Аккаунт", OtpUri.deviceName("  \n "))
    }

    @Test
    fun validatesSecret() {
        assertEquals("секрет не в формате Base32", OtpUri.validate(OtpAccount("x", "ABC1")))
        assertNull(OtpUri.validate(OtpAccount("x", "jbsw y3dp")))
    }

    @Test
    fun parsesFirmwareListLine() {
        val a = TokenViewModel.parseAccount("3|Old|Name|8|60|SHA512")!!
        assertEquals(3, a.index)
        assertEquals("Old|Name", a.name)
        assertEquals(8, a.digits)
        assertEquals(60, a.period)
        assertEquals("SHA512", a.algo)
    }
}
