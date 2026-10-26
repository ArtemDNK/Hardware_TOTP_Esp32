/*
 * ESP32-C6 TOTP Token
 * Аппаратный TOTP-аутентификатор (RFC 6238): ESP32-C6 + DS3231 + SSD1306 OLED + 3 кнопки.
 *
 *  - до 16 аккаунтов, SHA1 / SHA256 / SHA512, 6-8 цифр, произвольный период
 *  - PIN-код на устройстве, стирание всех данных после 10 неверных попыток
 *  - глубокий сон по таймауту, пробуждение любой кнопкой
 *  - настройка через USB (token_cli.py), секреты обратно не выдаются никогда
 *  - Wi-Fi / Bluetooth не используются вообще
 */

#include <Arduino.h>
#include <Wire.h>
#include <Preferences.h>
#include <U8g2lib.h>
#include <RTClib.h>
#include <mbedtls/md.h>
#include <esp_sleep.h>
#include <driver/rtc_io.h>
#include <sys/time.h>

#define FW_VERSION "1.0"

// ---------------------------------------------------------------- пины
static const uint8_t PIN_SDA      = 6;
static const uint8_t PIN_SCL      = 7;
static const uint8_t PIN_BTN_UP   = 2;   // LP GPIO (0..7) — нужны для пробуждения из deep sleep
static const uint8_t PIN_BTN_OK   = 3;
static const uint8_t PIN_BTN_DOWN = 4;

// ---------------------------------------------------------------- настройки
static const uint8_t  MAX_ACCOUNTS     = 16;
static const uint8_t  PIN_LEN          = 4;
static const uint8_t  MAX_PIN_FAILS    = 10;
static const uint32_t SLEEP_TIMEOUT_MS = 60000;
static const uint32_t LONG_PRESS_MS    = 800;
static const uint32_t DEBOUNCE_MS      = 30;
static const uint32_t MIN_VALID_TIME   = 1704067200UL;  // 2024-01-01

enum Algo : uint8_t { ALG_SHA1 = 0, ALG_SHA256 = 1, ALG_SHA512 = 2 };
static const char* ALGO_NAMES[] = {"SHA1", "SHA256", "SHA512"};

struct Account {
  char    name[32];
  uint8_t key[64];
  uint8_t keyLen;
  uint8_t digits;
  uint8_t period;
  uint8_t algo;
};

// ---------------------------------------------------------------- глобальное состояние
U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, U8X8_PIN_NONE);
RTC_DS3231 rtc;
Preferences prefs;

Account accounts[MAX_ACCOUNTS];
uint8_t accountCount = 0;
uint8_t current      = 0;

bool    rtcOk     = false;
bool    rtcLost   = false;
bool    pinSet    = false;
uint8_t pinHash[32];
uint8_t pinFails  = 0;
int16_t tzMinutes = 0;

bool     serialAuthed = false;
bool     displayOn    = true;
uint32_t lastActivity = 0;
uint32_t lastRedraw   = 0;

enum Screen { SCR_PIN, SCR_MAIN, SCR_MESSAGE };
Screen   screen = SCR_MAIN;
Screen   afterMessage = SCR_MAIN;
char     message[48];
uint32_t messageUntil = 0;

uint8_t pinEntry[PIN_LEN];
uint8_t pinPos = 0;

String serialLine;

// ---------------------------------------------------------------- кнопки
enum Ev { EV_NONE = 0, EV_SHORT, EV_LONG };

struct Button {
  uint8_t  pin;
  bool     pressed;
  bool     longFired;
  uint32_t changedAt;
  uint32_t downAt;
};

Button bUp   = {PIN_BTN_UP,   false, false, 0, 0};
Button bOk   = {PIN_BTN_OK,   false, false, 0, 0};
Button bDown = {PIN_BTN_DOWN, false, false, 0, 0};

void initButton(Button& b) {
#if SOC_RTCIO_INPUT_OUTPUT_SUPPORTED
  rtc_gpio_deinit((gpio_num_t)b.pin);  // после пробуждения пин мог остаться в LP-режиме
#endif
  pinMode(b.pin, INPUT_PULLUP);
  // Если кнопка зажата при старте (ей разбудили устройство) — игнорируем это нажатие.
  b.pressed   = digitalRead(b.pin) == LOW;
  b.longFired = b.pressed;
  b.changedAt = millis();
}

Ev pollButton(Button& b) {
  bool raw = digitalRead(b.pin) == LOW;
  uint32_t now = millis();
  if (raw != b.pressed && now - b.changedAt > DEBOUNCE_MS) {
    b.pressed = raw;
    b.changedAt = now;
    if (raw) {
      b.downAt = now;
      b.longFired = false;
    } else if (!b.longFired) {
      return EV_SHORT;
    }
  }
  if (b.pressed && !b.longFired && now - b.downAt > LONG_PRESS_MS) {
    b.longFired = true;
    return EV_LONG;
  }
  return EV_NONE;
}

// ---------------------------------------------------------------- криптография
int base32Decode(const char* in, uint8_t* out, int outMax) {
  uint32_t buffer = 0;
  int bits = 0, len = 0;
  for (const char* p = in; *p; ++p) {
    char c = *p;
    if (c == '=' || c == ' ' || c == '-') continue;
    int v;
    if (c >= 'A' && c <= 'Z')      v = c - 'A';
    else if (c >= 'a' && c <= 'z') v = c - 'a';
    else if (c >= '2' && c <= '7') v = c - '2' + 26;
    else return -1;
    buffer = (buffer << 5) | (uint32_t)v;
    bits += 5;
    if (bits >= 8) {
      if (len >= outMax) return -1;
      out[len++] = (buffer >> (bits - 8)) & 0xFF;
      bits -= 8;
    }
  }
  return len;
}

uint32_t computeTotp(const uint8_t* key, uint8_t keyLen, uint8_t algo,
                     uint8_t digits, uint8_t period, uint64_t t) {
  uint64_t counter = t / period;
  uint8_t msg[8];
  for (int i = 7; i >= 0; --i) { msg[i] = counter & 0xFF; counter >>= 8; }

  mbedtls_md_type_t mt = algo == ALG_SHA256 ? MBEDTLS_MD_SHA256
                       : algo == ALG_SHA512 ? MBEDTLS_MD_SHA512
                       : MBEDTLS_MD_SHA1;
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(mt);
  uint8_t h[64];
  mbedtls_md_hmac(info, key, keyLen, msg, sizeof msg, h);
  size_t hl = mbedtls_md_get_size(info);

  int off = h[hl - 1] & 0x0F;
  uint32_t bin = ((uint32_t)(h[off] & 0x7F) << 24) | ((uint32_t)h[off + 1] << 16) |
                 ((uint32_t)h[off + 2] << 8) | (uint32_t)h[off + 3];
  uint32_t mod = 1;
  for (uint8_t i = 0; i < digits; i++) mod *= 10;
  return bin % mod;
}

uint32_t totpFor(const Account& a, uint32_t t) {
  return computeTotp(a.key, a.keyLen, a.algo, a.digits, a.period, t);
}

void hashPin(const char* pin, uint8_t out[32]) {
  String s = String("esp32c6-totp-pin:") + pin;
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
             (const uint8_t*)s.c_str(), s.length(), out);
}

// ---------------------------------------------------------------- хранилище (NVS)
void accountKey(uint8_t i, char* k) { snprintf(k, 8, "a%u", i); }

void saveAll() {
  char k[8];
  for (uint8_t i = 0; i < accountCount; i++) {
    accountKey(i, k);
    prefs.putBytes(k, &accounts[i], sizeof(Account));
  }
  for (uint8_t i = accountCount; i < MAX_ACCOUNTS; i++) {
    accountKey(i, k);
    if (prefs.isKey(k)) prefs.remove(k);
  }
  prefs.putUChar("n", accountCount);
}

void loadAll() {
  accountCount = prefs.getUChar("n", 0);
  if (accountCount > MAX_ACCOUNTS) accountCount = 0;
  char k[8];
  for (uint8_t i = 0; i < accountCount; i++) {
    accountKey(i, k);
    if (prefs.getBytes(k, &accounts[i], sizeof(Account)) != sizeof(Account)) {
      accountCount = i;
      break;
    }
  }
  pinSet    = prefs.getBytes("pinh", pinHash, sizeof pinHash) == sizeof pinHash;
  pinFails  = prefs.getUChar("fails", 0);
  tzMinutes = prefs.getShort("tz", 0);
}

void wipeAll() {
  prefs.clear();
  memset(accounts, 0, sizeof accounts);
  memset(pinHash, 0, sizeof pinHash);
  accountCount = 0;
  current = 0;
  pinSet = false;
  pinFails = 0;
  tzMinutes = 0;
  serialAuthed = false;
}

enum PinResult { PIN_OK, PIN_BAD, PIN_WIPED };

PinResult verifyPin(const char* pin) {
  // Счётчик увеличиваем ДО проверки: отключение питания после неудачи не сбросит его.
  pinFails++;
  prefs.putUChar("fails", pinFails);

  uint8_t h[32];
  hashPin(pin, h);
  uint8_t diff = 0;
  for (int i = 0; i < 32; i++) diff |= h[i] ^ pinHash[i];

  if (diff == 0) {
    pinFails = 0;
    prefs.putUChar("fails", 0);
    return PIN_OK;
  }
  if (pinFails >= MAX_PIN_FAILS) {
    wipeAll();
    return PIN_WIPED;
  }
  delay(min<uint32_t>(pinFails * 500UL, 5000UL));
  return PIN_BAD;
}

// ---------------------------------------------------------------- время
uint32_t nowUtc() {
  if (rtcOk && !rtcLost) return rtc.now().unixtime();
  return (uint32_t)time(nullptr);
}

bool timeValid(uint32_t t) { return t > MIN_VALID_TIME; }

void setUtc(uint32_t t) {
  if (rtcOk) {
    rtc.adjust(DateTime(t));
    rtcLost = false;
  }
  struct timeval tv = {(time_t)t, 0};
  settimeofday(&tv, nullptr);
}

// ---------------------------------------------------------------- экран
void showMessage(const char* msg, uint32_t ms, Screen next) {
  strncpy(message, msg, sizeof message - 1);
  message[sizeof message - 1] = 0;
  messageUntil = millis() + ms;
  afterMessage = next;
  screen = SCR_MESSAGE;
}

void drawCentered(int y, const char* s) {
  int w = u8g2.getUTF8Width(s);
  u8g2.drawUTF8((128 - w) / 2, y, s);
}

void drawStatusLine(uint32_t t, uint8_t period) {
  u8g2.setFont(u8g2_font_6x12_t_cyrillic);
  if (!timeValid(t)) return;
  if (period) {
    char s[8];
    snprintf(s, sizeof s, "%2us", (unsigned)(period - t % period));
    u8g2.drawStr(0, 63, s);
  }
  DateTime local(t + (int32_t)tzMinutes * 60);
  char c[12];
  snprintf(c, sizeof c, "%02d:%02d:%02d", local.hour(), local.minute(), local.second());
  u8g2.drawStr(128 - u8g2.getStrWidth(c), 63, c);
}

void drawCode(uint32_t code, uint8_t digits) {
  char s[12];
  snprintf(s, sizeof s, "%0*lu", (int)digits, (unsigned long)code);
  uint8_t half = (digits + 1) / 2;
  char a[8], b[8];
  memcpy(a, s, half);
  a[half] = 0;
  strcpy(b, s + half);

  u8g2.setFont(digits > 6 ? u8g2_font_logisoso20_tn : u8g2_font_logisoso24_tn);
  int wa = u8g2.getStrWidth(a), wb = u8g2.getStrWidth(b), gap = 10;
  int x = (128 - (wa + gap + wb)) / 2;
  u8g2.drawStr(x, 44, a);
  u8g2.drawStr(x + wa + gap, 44, b);
}

void drawMain() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x12_t_cyrillic);
  uint32_t t = nowUtc();

  if (accountCount == 0) {
    drawCentered(14, "Нет аккаунтов");
    drawCentered(32, "Подключите USB и");
    drawCentered(44, "запустите token_cli");
    drawStatusLine(t, 0);
    u8g2.sendBuffer();
    return;
  }

  const Account& a = accounts[current];
  char hdr[48];
  snprintf(hdr, sizeof hdr, "%u/%u %s", current + 1, accountCount, a.name);
  u8g2.drawUTF8(0, 10, hdr);
  u8g2.drawHLine(0, 13, 128);

  if (!timeValid(t)) {
    drawCentered(32, "Время не задано");
    drawCentered(46, "token_cli.py sync");
    u8g2.sendBuffer();
    return;
  }

  drawCode(totpFor(a, t), a.digits);

  uint32_t remaining = a.period - t % a.period;
  u8g2.drawFrame(0, 49, 128, 4);
  u8g2.drawBox(0, 49, 128 * remaining / a.period, 4);
  drawStatusLine(t, a.period);
  u8g2.sendBuffer();
}

void drawPin() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x12_t_cyrillic);
  drawCentered(12, "Введите PIN");

  for (uint8_t i = 0; i < PIN_LEN; i++) {
    int x = 14 + i * 26;
    if (i < pinPos) {
      u8g2.drawDisc(x + 8, 34, 5);
    } else if (i == pinPos) {
      u8g2.setFont(u8g2_font_logisoso20_tn);
      char d[2] = {(char)('0' + pinEntry[i]), 0};
      u8g2.drawStr(x + 2, 44, d);
      u8g2.drawFrame(x - 2, 18, 22, 30);
    } else {
      u8g2.drawHLine(x, 44, 16);
    }
  }

  u8g2.setFont(u8g2_font_6x12_t_cyrillic);
  if (pinFails > 0) {
    char s[32];
    snprintf(s, sizeof s, "Осталось попыток: %u", MAX_PIN_FAILS - pinFails);
    drawCentered(62, s);
  } else {
    drawCentered(62, "OK - далее");
  }
  u8g2.sendBuffer();
}

void drawMessage() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x12_t_cyrillic);
  drawCentered(36, message);
  u8g2.sendBuffer();
}

void redraw() {
  switch (screen) {
    case SCR_PIN:     drawPin(); break;
    case SCR_MAIN:    drawMain(); break;
    case SCR_MESSAGE: drawMessage(); break;
  }
  lastRedraw = millis();
}

// ---------------------------------------------------------------- сон / блокировка
void resetPinEntry() {
  memset(pinEntry, 0, sizeof pinEntry);
  pinPos = 0;
}

void lockDevice() {
  serialAuthed = false;
  if (pinSet) {
    resetPinEntry();
    screen = SCR_PIN;
  }
}

void goToSleep() {
  u8g2.setPowerSave(1);
  Serial.flush();

  // Ждём отпускания кнопок, иначе устройство сразу проснётся.
  while (digitalRead(PIN_BTN_UP) == LOW || digitalRead(PIN_BTN_OK) == LOW ||
         digitalRead(PIN_BTN_DOWN) == LOW) {
    delay(10);
  }
  delay(50);

  const uint8_t pins[] = {PIN_BTN_UP, PIN_BTN_OK, PIN_BTN_DOWN};
  uint64_t mask = 0;
  for (uint8_t p : pins) {
    mask |= 1ULL << p;
#if SOC_RTCIO_INPUT_OUTPUT_SUPPORTED
    rtc_gpio_pulldown_dis((gpio_num_t)p);
    rtc_gpio_pullup_en((gpio_num_t)p);
#endif
  }
#if SOC_PM_SUPPORT_RTC_PERIPH_PD
  esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_PERIPH, ESP_PD_OPTION_ON);
#endif
  esp_sleep_enable_ext1_wakeup(mask, ESP_EXT1_WAKEUP_ANY_LOW);
  esp_deep_sleep_start();
}

bool usbHostConnected() { return (bool)Serial; }

void onIdleTimeout() {
  lockDevice();
  if (usbHostConnected()) {
    // Подключены к компьютеру — не засыпаем (иначе пропадёт COM-порт), только гасим экран.
    u8g2.setPowerSave(1);
    displayOn = false;
  } else {
    goToSleep();
  }
}

// ---------------------------------------------------------------- USB-консоль
void reply(bool ok, const char* err = nullptr) {
  if (ok) Serial.println("OK");
  else { Serial.print("ERR "); Serial.println(err ? err : "error"); }
}

String nextToken(String& s) {
  s.trim();
  int sp = s.indexOf(' ');
  String tok = sp < 0 ? s : s.substring(0, sp);
  s = sp < 0 ? String() : s.substring(sp + 1);
  return tok;
}

bool runSelfTest() {
  // Тестовые векторы RFC 6238, T = 59 и T = 1111111109
  const char* k1 = "12345678901234567890";
  const char* k2 = "12345678901234567890123456789012";
  const char* k3 = "1234567890123456789012345678901234567890123456789012345678901234";
  struct { const char* k; uint8_t algo; uint32_t t; uint32_t expect; } v[] = {
    {k1, ALG_SHA1,   59,         94287082},
    {k2, ALG_SHA256, 59,         46119246},
    {k3, ALG_SHA512, 59,         90693936},
    {k1, ALG_SHA1,   1111111109, 7081804},
    {k2, ALG_SHA256, 1111111109, 68084774},
    {k3, ALG_SHA512, 1111111109, 25091201},
  };
  bool all = true;
  for (auto& c : v) {
    uint32_t r = computeTotp((const uint8_t*)c.k, strlen(c.k), c.algo, 8, 30, c.t);
    bool ok = r == c.expect;
    all &= ok;
    Serial.printf("%s T=%lu %08lu %s\n", ALGO_NAMES[c.algo], (unsigned long)c.t,
                  (unsigned long)r, ok ? "pass" : "FAIL");
  }
  return all;
}

void printHelp() {
  Serial.println("help                      - эта справка");
  Serial.println("info                      - состояние устройства");
  Serial.println("auth <pin>                - авторизация консоли");
  Serial.println("logout                    - выйти");
  Serial.println("list                      - список аккаунтов");
  Serial.println("add <b32> <dig> <per> <alg> <name> - добавить");
  Serial.println("del <n>                   - удалить аккаунт n");
  Serial.println("move <n> <m>              - переместить аккаунт");
  Serial.println("time [unix]               - показать/задать время UTC");
  Serial.println("tz <minutes>              - смещение часового пояса для часов");
  Serial.println("setpin <pin|off>          - задать/снять PIN");
  Serial.println("selftest                  - проверка по RFC 6238");
  Serial.println("wipe YES                  - стереть всё");
}

void processCommand(String line) {
  line.trim();
  if (line.length() == 0) return;
  String args = line;
  String cmd = nextToken(args);
  cmd.toLowerCase();

  if (cmd == "help") { printHelp(); reply(true); return; }

  if (cmd == "info") {
    Serial.printf("fw=%s\n", FW_VERSION);
    Serial.printf("accounts=%u/%u\n", accountCount, MAX_ACCOUNTS);
    Serial.printf("pin=%d\n", pinSet ? 1 : 0);
    Serial.printf("auth=%d\n", (!pinSet || serialAuthed) ? 1 : 0);
    Serial.printf("fails=%u\n", pinFails);
    Serial.printf("rtc=%s\n", rtcOk ? "ds3231" : "none");
    Serial.printf("rtc_lost=%d\n", rtcLost ? 1 : 0);
    Serial.printf("time=%lu\n", (unsigned long)nowUtc());
    Serial.printf("tz=%d\n", tzMinutes);
    reply(true);
    return;
  }

  if (cmd == "auth") {
    if (!pinSet) { serialAuthed = true; reply(true); return; }
    String p = nextToken(args);
    PinResult r = verifyPin(p.c_str());
    if (r == PIN_OK) { serialAuthed = true; reply(true); }
    else if (r == PIN_WIPED) { reply(false, "too many attempts, device wiped"); }
    else { reply(false, "wrong pin"); }
    return;
  }

  if (cmd == "logout") { serialAuthed = false; reply(true); return; }

  if (pinSet && !serialAuthed) { reply(false, "auth required"); return; }

  if (cmd == "list") {
    for (uint8_t i = 0; i < accountCount; i++) {
      const Account& a = accounts[i];
      Serial.printf("%u|%s|%u|%u|%s\n", i + 1, a.name, a.digits, a.period, ALGO_NAMES[a.algo]);
    }
    reply(true);
    return;
  }

  if (cmd == "add") {
    if (accountCount >= MAX_ACCOUNTS) { reply(false, "storage full"); return; }
    String b32 = nextToken(args);
    int digits = nextToken(args).toInt();
    int period = nextToken(args).toInt();
    String alg = nextToken(args);
    alg.toUpperCase();
    args.trim();
    String name = args;

    Account a;
    memset(&a, 0, sizeof a);
    int len = base32Decode(b32.c_str(), a.key, sizeof a.key);
    if (len <= 0) { reply(false, "bad secret"); return; }
    if (digits < 6 || digits > 8) { reply(false, "digits must be 6..8"); return; }
    if (period < 10 || period > 255) { reply(false, "period must be 10..255"); return; }
    if (alg == "SHA1") a.algo = ALG_SHA1;
    else if (alg == "SHA256") a.algo = ALG_SHA256;
    else if (alg == "SHA512") a.algo = ALG_SHA512;
    else { reply(false, "algo must be SHA1/SHA256/SHA512"); return; }
    if (name.length() == 0 || name.length() >= sizeof a.name) { reply(false, "name must be 1..31 bytes"); return; }

    a.keyLen = len;
    a.digits = digits;
    a.period = period;
    strncpy(a.name, name.c_str(), sizeof a.name - 1);
    accounts[accountCount++] = a;
    saveAll();
    memset(&a, 0, sizeof a);
    reply(true);
    return;
  }

  if (cmd == "del") {
    int n = nextToken(args).toInt();
    if (n < 1 || n > accountCount) { reply(false, "bad index"); return; }
    for (uint8_t i = n - 1; i + 1 < accountCount; i++) accounts[i] = accounts[i + 1];
    accountCount--;
    memset(&accounts[accountCount], 0, sizeof(Account));
    if (current >= accountCount) current = accountCount ? accountCount - 1 : 0;
    saveAll();
    reply(true);
    return;
  }

  if (cmd == "move") {
    int from = nextToken(args).toInt();
    int to = nextToken(args).toInt();
    if (from < 1 || from > accountCount || to < 1 || to > accountCount) { reply(false, "bad index"); return; }
    Account tmp = accounts[from - 1];
    if (from < to) for (int i = from - 1; i < to - 1; i++) accounts[i] = accounts[i + 1];
    else           for (int i = from - 1; i > to - 1; i--) accounts[i] = accounts[i - 1];
    accounts[to - 1] = tmp;
    memset(&tmp, 0, sizeof tmp);
    saveAll();
    reply(true);
    return;
  }

  if (cmd == "time") {
    String v = nextToken(args);
    if (v.length()) {
      uint32_t t = strtoul(v.c_str(), nullptr, 10);
      if (!timeValid(t)) { reply(false, "bad time"); return; }
      setUtc(t);
    }
    Serial.printf("time=%lu\n", (unsigned long)nowUtc());
    reply(true);
    return;
  }

  if (cmd == "tz") {
    int m = nextToken(args).toInt();
    if (m < -720 || m > 840) { reply(false, "tz out of range"); return; }
    tzMinutes = m;
    prefs.putShort("tz", tzMinutes);
    reply(true);
    return;
  }

  if (cmd == "setpin") {
    String p = nextToken(args);
    if (p == "off") {
      prefs.remove("pinh");
      pinSet = false;
      reply(true);
      return;
    }
    if (p.length() != PIN_LEN) { reply(false, "pin must be 4 digits"); return; }
    for (char c : p) if (c < '0' || c > '9') { reply(false, "pin must be digits"); return; }
    hashPin(p.c_str(), pinHash);
    prefs.putBytes("pinh", pinHash, sizeof pinHash);
    pinSet = true;
    pinFails = 0;
    prefs.putUChar("fails", 0);
    reply(true);
    return;
  }

  if (cmd == "selftest") { reply(runSelfTest(), "selftest failed"); return; }

  if (cmd == "wipe") {
    if (nextToken(args) != "YES") { reply(false, "type: wipe YES"); return; }
    wipeAll();
    screen = SCR_MAIN;
    reply(true);
    return;
  }

  reply(false, "unknown command, see help");
}

void handleSerial() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      processCommand(serialLine);
      serialLine = "";
      lastActivity = millis();
      if (screen == SCR_MAIN) redraw();
    } else if (serialLine.length() < 300) {
      serialLine += c;
    }
  }
}

// ---------------------------------------------------------------- обработка кнопок
void handlePinScreen(Ev up, Ev ok, Ev dn) {
  if (up) pinEntry[pinPos] = (pinEntry[pinPos] + 1) % 10;
  if (dn) pinEntry[pinPos] = (pinEntry[pinPos] + 9) % 10;
  if (ok == EV_LONG && pinPos > 0) { pinPos--; return; }
  if (ok != EV_SHORT) return;

  if (++pinPos < PIN_LEN) return;

  char p[PIN_LEN + 1];
  for (uint8_t i = 0; i < PIN_LEN; i++) p[i] = '0' + pinEntry[i];
  p[PIN_LEN] = 0;
  resetPinEntry();

  showMessage("Проверка...", 0, SCR_PIN);
  redraw();
  PinResult r = verifyPin(p);
  memset(p, 0, sizeof p);

  if (r == PIN_OK)         { screen = SCR_MAIN; }
  else if (r == PIN_WIPED) { showMessage("Данные стёрты", 3000, SCR_MAIN); }
  else                     { showMessage("Неверный PIN", 1500, SCR_PIN); }
}

void handleMainScreen(Ev up, Ev ok, Ev dn) {
  if (accountCount > 0) {
    if (up) current = current == 0 ? accountCount - 1 : current - 1;
    if (dn) current = (current + 1) % accountCount;
  }
  if (ok == EV_LONG) {
    lockDevice();
    if (usbHostConnected()) { u8g2.setPowerSave(1); displayOn = false; }
    else goToSleep();
  }
}

// ---------------------------------------------------------------- setup / loop
void setup() {
  Serial.begin(115200);

  initButton(bUp);
  initButton(bOk);
  initButton(bDown);

  Wire.begin(PIN_SDA, PIN_SCL);
  Wire.setClock(400000);
  u8g2.begin();
  u8g2.enableUTF8Print();

  rtcOk = rtc.begin(&Wire);
  if (rtcOk) {
    rtcLost = rtc.lostPower();
    if (!rtcLost) {
      struct timeval tv = {(time_t)rtc.now().unixtime(), 0};
      settimeofday(&tv, nullptr);
    }
  }

  prefs.begin("totp", false);
  loadAll();

  resetPinEntry();
  screen = pinSet ? SCR_PIN : SCR_MAIN;
  if (!rtcOk) showMessage("DS3231 не найден", 2000, screen);
  else if (rtcLost) showMessage("RTC сброшен!", 2000, screen);

  lastActivity = millis();
  redraw();
}

void loop() {
  handleSerial();

  Ev up = pollButton(bUp);
  Ev ok = pollButton(bOk);
  Ev dn = pollButton(bDown);
  bool any = up || ok || dn;
  uint32_t now = millis();

  if (any) lastActivity = now;

  if (!displayOn) {
    if (any) {  // первое нажатие только будит экран
      displayOn = true;
      u8g2.setPowerSave(0);
      redraw();
    }
    delay(10);
    return;
  }

  switch (screen) {
    case SCR_PIN:  if (any) handlePinScreen(up, ok, dn); break;
    case SCR_MAIN: if (any) handleMainScreen(up, ok, dn); break;
    case SCR_MESSAGE:
      if ((int32_t)(now - messageUntil) >= 0) screen = afterMessage;
      break;
  }

  if (displayOn && (any || now - lastRedraw > 200)) redraw();

  if (displayOn && now - lastActivity > SLEEP_TIMEOUT_MS) onIdleTimeout();

  delay(10);
}
