@file:OptIn(ExperimentalMaterial3Api::class)

package dev.artemdnk.totptoken

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlin.math.abs

private sealed interface DialogState {
    data object Auth : DialogState
    data object Paste : DialogState
    data object Manual : DialogState
    data object SetPin : DialogState
    data object Wipe : DialogState
    data class Delete(val account: TokenAccount) : DialogState
}

private const val MAX_ACCOUNTS = 16
private const val MAX_PIN_FAILS = 10

@Composable
fun TokenScreen(vm: TokenViewModel, onConnect: () -> Unit) {
    val s = vm.state
    val snackbar = remember { SnackbarHostState() }
    var dialog by remember { mutableStateOf<DialogState?>(null) }

    LaunchedEffect(Unit) { vm.messages.collect { snackbar.showSnackbar(it) } }
    LaunchedEffect(s.connected, s.authed) {
        if (s.connected && !s.authed) dialog = DialogState.Auth
    }

    val scanner = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { vm.addFromText(it) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("TOTP Token") },
                actions = {
                    if (s.connected) {
                        IconButton(onClick = { vm.refresh() }, enabled = !s.busy) {
                            Icon(Icons.Default.Refresh, contentDescription = "Обновить")
                        }
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { StatusCard(s, onConnect = onConnect, onDisconnect = { vm.disconnect() }) }
            if (s.busy) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }

            if (s.connected && !s.authed) {
                item {
                    Button(onClick = { dialog = DialogState.Auth }, modifier = Modifier.fillMaxWidth()) {
                        Text("Ввести PIN")
                    }
                }
            }

            if (s.connected && s.authed) {
                item { SectionTitle("Добавить аккаунт") }
                item {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = {
                                scanner.launch(
                                    ScanOptions()
                                        .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                        .setPrompt("Наведите камеру на QR-код 2FA")
                                        .setBeepEnabled(false)
                                        .setOrientationLocked(false)
                                )
                            },
                            enabled = !s.busy && s.accounts.size < MAX_ACCOUNTS,
                            modifier = Modifier.weight(1f),
                        ) { Text("QR-код") }
                        OutlinedButton(
                            onClick = { dialog = DialogState.Paste },
                            enabled = !s.busy && s.accounts.size < MAX_ACCOUNTS,
                            modifier = Modifier.weight(1f),
                        ) { Text("Ссылка") }
                        OutlinedButton(
                            onClick = { dialog = DialogState.Manual },
                            enabled = !s.busy && s.accounts.size < MAX_ACCOUNTS,
                            modifier = Modifier.weight(1f),
                        ) { Text("Вручную") }
                    }
                }

                item { SectionTitle("Аккаунты (${s.accounts.size}/$MAX_ACCOUNTS)") }
                if (s.accounts.isEmpty()) {
                    item {
                        Text(
                            "Пока пусто. Отсканируйте QR-код со страницы включения 2FA " +
                                "или экспорт из Google Authenticator.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                items(s.accounts, key = { "${it.index}:${it.name}" }) { a ->
                    AccountRow(
                        account = a,
                        canUp = a.index > 1,
                        canDown = a.index < s.accounts.size,
                        enabled = !s.busy,
                        onUp = { vm.move(a.index, a.index - 1) },
                        onDown = { vm.move(a.index, a.index + 1) },
                        onDelete = { dialog = DialogState.Delete(a) },
                    )
                }

                item { SectionTitle("Настройки") }
                item {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { vm.syncTime() }, enabled = !s.busy, modifier = Modifier.fillMaxWidth()) {
                            Text("Синхронизировать время и часовой пояс")
                        }
                        OutlinedButton(onClick = { dialog = DialogState.SetPin }, enabled = !s.busy, modifier = Modifier.fillMaxWidth()) {
                            Text(if (s.pinSet) "Изменить или снять PIN" else "Задать PIN")
                        }
                        OutlinedButton(onClick = { vm.selfTest() }, enabled = !s.busy, modifier = Modifier.fillMaxWidth()) {
                            Text("Самотест (RFC 6238)")
                        }
                        OutlinedButton(
                            onClick = { dialog = DialogState.Wipe },
                            enabled = !s.busy,
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                        ) { Text("Стереть токен") }
                    }
                }
            }
        }
    }

    val close = { dialog = null }
    when (val d = dialog) {
        null -> Unit
        DialogState.Auth -> PinDialog(
            title = "PIN токена",
            hint = if (s.pinFails > 0) "Осталось попыток: ${MAX_PIN_FAILS - s.pinFails}. " +
                "После ${MAX_PIN_FAILS} ошибок токен сотрёт все данные." else null,
            confirm = "Войти",
            repeat = false,
            onConfirm = { pin -> close(); vm.auth(pin) },
            onDismiss = close,
        )
        DialogState.SetPin -> PinDialog(
            title = if (s.pinSet) "Новый PIN" else "Задать PIN",
            hint = "4 цифры. Вводится кнопками на токене при включении.",
            confirm = "Сохранить",
            repeat = true,
            onConfirm = { pin -> close(); vm.setPin(pin) },
            onDismiss = close,
            onRemove = if (s.pinSet) ({ close(); vm.setPin(null) }) else null,
        )
        DialogState.Paste -> PasteDialog(onConfirm = { text -> close(); vm.addFromText(text) }, onDismiss = close)
        DialogState.Manual -> ManualDialog(onConfirm = { acc -> close(); vm.addManual(acc) }, onDismiss = close)
        DialogState.Wipe -> AlertDialog(
            onDismissRequest = close,
            title = { Text("Стереть токен?") },
            text = { Text("Будут удалены все аккаунты, PIN и настройки. Отменить это нельзя.") },
            confirmButton = {
                TextButton(onClick = { close(); vm.wipe() }) {
                    Text("Стереть", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = close) { Text("Отмена") } },
        )
        is DialogState.Delete -> AlertDialog(
            onDismissRequest = close,
            title = { Text("Удалить аккаунт?") },
            text = {
                Text("«${d.account.name}» будет удалён с токена. Убедитесь, что у вас есть другой способ входа или резервные коды.")
            },
            confirmButton = {
                TextButton(onClick = { close(); vm.delete(d.account.index) }) {
                    Text("Удалить", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = close) { Text("Отмена") } },
        )
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 8.dp),
    )
}

@Composable
private fun StatusCard(s: UiState, onConnect: () -> Unit, onDisconnect: () -> Unit) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            if (!s.connected) {
                Text("Токен не подключён", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Подключите токен к телефону кабелем USB-C ↔ USB-C или через OTG-переходник. " +
                        "На плате DevKitC — разъём «USB», не «UART».",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
                Button(onClick = onConnect, enabled = !s.busy) { Text("Подключить") }
            } else {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Токен подключён", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                    TextButton(onClick = onDisconnect) { Text("Отключить") }
                }
                InfoLine("Прошивка", s.info["fw"] ?: "—")
                InfoLine("Аккаунты", s.info["accounts"] ?: "—")
                InfoLine("PIN", if (s.pinSet) "установлен" else "не задан", warn = !s.pinSet)
                InfoLine("Часы", rtcText(s), warn = s.info["rtc"] != "ds3231" || s.info["rtc_lost"] == "1")
                val (timeText, timeWarn) = timeText(s)
                InfoLine("Время", timeText, warn = timeWarn)
                if (s.pinFails > 0) InfoLine("Ошибок PIN", "${s.pinFails} из $MAX_PIN_FAILS", warn = true)
            }
        }
    }
}

private fun rtcText(s: UiState): String = when {
    s.info["rtc"] != "ds3231" -> "DS3231 не найден"
    s.info["rtc_lost"] == "1" -> "сброшены, нужна синхронизация"
    else -> "DS3231"
}

private fun timeText(s: UiState): Pair<String, Boolean> {
    val t = s.info["time"]?.toLongOrNull() ?: return "—" to false
    val drift = s.timeDrift ?: return "—" to false
    if (t < 1704067200L) return "не задано — синхронизируйте" to true
    val text = when {
        drift == 0L -> "точно"
        drift > 0 -> "спешит на ${abs(drift)} с"
        else -> "отстаёт на ${abs(drift)} с"
    }
    return text to (abs(drift) > 10)
}

@Composable
private fun InfoLine(label: String, value: String, warn: Boolean = false) {
    Row(Modifier.fillMaxWidth()) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
        Text(
            value,
            color = if (warn) MaterialTheme.colorScheme.error else Color.Unspecified,
            fontWeight = if (warn) FontWeight.Medium else FontWeight.Normal,
        )
    }
}

@Composable
private fun AccountRow(
    account: TokenAccount,
    canUp: Boolean,
    canDown: Boolean,
    enabled: Boolean,
    onUp: () -> Unit,
    onDown: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(start = 16.dp, end = 4.dp, top = 8.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    "${account.index}. ${account.name}",
                    style = MaterialTheme.typography.bodyLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    "${account.digits} цифр · ${account.period} с · ${account.algo}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            IconButton(onClick = onUp, enabled = enabled && canUp) {
                Icon(Icons.Default.KeyboardArrowUp, contentDescription = "Выше")
            }
            IconButton(onClick = onDown, enabled = enabled && canDown) {
                Icon(Icons.Default.KeyboardArrowDown, contentDescription = "Ниже")
            }
            IconButton(onClick = onDelete, enabled = enabled) {
                Icon(Icons.Default.Delete, contentDescription = "Удалить")
            }
        }
    }
}

@Composable
private fun PinDialog(
    title: String,
    hint: String?,
    confirm: String,
    repeat: Boolean,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
    onRemove: (() -> Unit)? = null,
) {
    var pin by remember { mutableStateOf("") }
    var pin2 by remember { mutableStateOf("") }
    val valid = pin.length == 4 && (!repeat || pin == pin2)
    val pinKeyboard = KeyboardOptions(keyboardType = KeyboardType.NumberPassword)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (hint != null) Text(hint, style = MaterialTheme.typography.bodyMedium)
                OutlinedTextField(
                    value = pin,
                    onValueChange = { v -> pin = v.filter(Char::isDigit).take(4) },
                    label = { Text("PIN") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = pinKeyboard,
                )
                if (repeat) {
                    OutlinedTextField(
                        value = pin2,
                        onValueChange = { v -> pin2 = v.filter(Char::isDigit).take(4) },
                        label = { Text("Повторите PIN") },
                        singleLine = true,
                        isError = pin2.length == 4 && pin != pin2,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = pinKeyboard,
                    )
                }
                if (onRemove != null) {
                    TextButton(onClick = onRemove) {
                        Text("Снять PIN", color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(pin) }, enabled = valid) { Text(confirm) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}

@Composable
private fun PasteDialog(onConfirm: (String) -> Unit, onDismiss: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    var text by remember {
        val clip = clipboard.getText()?.text?.trim().orEmpty()
        mutableStateOf(if (clip.startsWith("otpauth", ignoreCase = true)) clip else "")
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Добавить по ссылке") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Ссылка otpauth://… или экспорт Google Authenticator otpauth-migration://…",
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    label = { Text("Ссылка") },
                    minLines = 3,
                    maxLines = 6,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(text) }, enabled = text.isNotBlank()) { Text("Добавить") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}

@Composable
private fun ManualDialog(onConfirm: (OtpAccount) -> Unit, onDismiss: () -> Unit) {
    var name by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf("") }
    var period by remember { mutableStateOf("30") }
    var digits by remember { mutableStateOf(6) }
    var algo by remember { mutableStateOf("SHA1") }

    val account = OtpAccount(name.trim(), Base32.normalize(secret), digits, period.toIntOrNull() ?: 0, algo)
    val error = when {
        name.isBlank() -> "Укажите название"
        secret.isBlank() -> null
        else -> OtpUri.validate(account)
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Добавить вручную") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Название") },
                    singleLine = true,
                    supportingText = { Text("${OtpUri.deviceName(name).toByteArray().size}/31 байт на экране токена") },
                )
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    label = { Text("Секретный ключ (Base32)") },
                    singleLine = true,
                    isError = secret.isNotBlank() && error != null,
                    supportingText = { if (secret.isNotBlank() && error != null) Text(error) },
                )
                OutlinedTextField(
                    value = period,
                    onValueChange = { v -> period = v.filter(Char::isDigit).take(3) },
                    label = { Text("Период, с") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
                Text("Цифр", style = MaterialTheme.typography.labelLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(6, 8).forEach { d ->
                        FilterChip(selected = digits == d, onClick = { digits = d }, label = { Text("$d") })
                    }
                }
                Text("Алгоритм", style = MaterialTheme.typography.labelLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OtpUri.ALGOS.forEach { a ->
                        FilterChip(selected = algo == a, onClick = { algo = a }, label = { Text(a) })
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(account) }, enabled = secret.isNotBlank() && error == null) {
                Text("Добавить")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}
