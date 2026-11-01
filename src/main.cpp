/*
 * Hardware TOTP on ESP32-C6
 * Аппаратный TOTP-аутентификатор (RFC 6238):
 * ESP32-C6 + DS3231 + модуль 1.3" OLED SH1106 с энкодером EC11 и кнопками BACK / CONFIRM.
 *
 *  - до 16 аккаунтов, SHA1 / SHA256 / SHA512, 6-8 цифр, произвольный период
 *  - список аккаунтов и меню настроек на самом токене (яркость, автосон, поворот экрана)
 *  - PIN-код вводится ручкой, стирание всех данных после 10 неверных попыток
 *  - глубокий сон по таймауту, пробуждение кнопкой или нажатием ручки
 *  - настройка через USB (tools/token_cli.py или Android-приложение), секреты обратно не выдаются
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
#include <driver/pulse_cnt.h>
#include <sys/time.h>

#define FW_VERSION "2.0"

// ---------------------------------------------------------------- пины
// Разъём модуля: CON SDA SCL PSH TRA TRB BAK GND VCC
static const uint8_t PIN_SDA   = 6;   // SDA
static const uint8_t PIN_SCL   = 7;   // SCL
static const uint8_t PIN_CON   = 2;   // CON — кнопка CONFIRM     } LP GPIO 0..7:
static const uint8_t PIN_BAK   = 3;   // BAK — кнопка BACK        } только они будят
static const uint8_t PIN_PSH   = 4;   // PSH — нажатие на ручку   } ESP32-C6 из deep sleep
static const uint8_t PIN_ENC_A = 18;  // TRA — энкодер, фаза A
static const uint8_t PIN_ENC_B = 19;  // TRB — энкодер, фаза B

// ---------------------------------------------------------------- настройки
static const uint8_t  MAX_ACCOUNTS     = 16;
static const uint8_t  PIN_LEN          = 4;
static const uint8_t  MAX_PIN_FAILS    = 10;
static const uint32_t LONG_PRESS_MS    = 700;
static const uint32_t DEBOUNCE_MS      = 30;
static const uint32_t MIN_VALID_TIME   = 1704067200UL;  // 2024-01-01

// EC11 «20 импульсов / 20 щелчков»: один щелчок = полный цикл = 4 перехода.
// Если ручка прыгает на 2 пункта за щелчок — поставьте 2. Не в ту сторону — ENC_DIR = -1.
static const int ENC_STEPS_PER_DETENT = 4;
static const int ENC_DIR              = 1;

static const uint16_t SLEEP_OPTIONS[] = {15, 30, 60, 120, 300};  // секунды
static const uint8_t  SLEEP_OPTION_COUNT = sizeof(SLEEP_OPTIONS) / sizeof(SLEEP_OPTIONS[0]);
static const uint8_t  BRIGHTNESS_LEVELS  = 10;

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
U8G2_SH1106_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, U8X8_PIN_NONE);
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

uint8_t brightness = 7;   // 1..10
uint8_t sleepIdx   = 2;   // индекс в SLEEP_OPTIONS (60 с)
bool    flipped    = false;

bool     serialAuthed = false;
bool     displayOn    = true;
uint32_t lastActivity = 0;
uint32_t lastRedraw   = 0;

enum Screen { SCR_PIN, SCR_CODE, SCR_LIST, SCR_MENU, SCR_ABOUT, SCR_MESSAGE };
Screen   screen = SCR_CODE;
Screen   afterMessage = SCR_CODE;
char     message[48];
uint32_t messageUntil = 0;

uint8_t listCursor = 0;
uint8_t menuCursor = 0;
bool    menuEditing = false;

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

Button bCon = {PIN_CON, false, false, 0, 0};
Button bBak = {PIN_BAK, false, false, 0, 0};
Button bPsh = {PIN_PSH, false, false, 0, 0};

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

bool anyButtonDown() {
  return digitalRead(PIN_CON) == LOW || digitalRead(PIN_BAK) == LOW || digitalRead(PIN_PSH) == LOW;
}

// ---------------------------------------------------------------- энкодер (аппаратный счётчик PCNT)
pcnt_unit_handle_t encUnit = nullptr;
int encConsumed = 0;

bool initEncoder() {
  pcnt_unit_config_t uc = {};
  uc.low_limit  = -10000;
  uc.high_limit = 10000;
  if (pcnt_new_unit(&uc, &encUnit) != ESP_OK) return false;

  pcnt_glitch_filter_config_t filter = {};
  filter.max_glitch_ns = 1000;
  pcnt_unit_set_glitch_filter(encUnit, &filter);

  // Классическая квадратурная схема x4: каждый канал считает фронты своей фазы,
  // направление определяется уровнем другой фазы. Подтяжки включает драйвер.
  pcnt_chan_config_t ca = {};
  ca.edge_gpio_num  = PIN_ENC_A;
  ca.level_gpio_num = PIN_ENC_B;
  pcnt_channel_handle_t chA;
  pcnt_new_channel(encUnit, &ca, &chA);

  pcnt_chan_config_t cb = {};
  cb.edge_gpio_num  = PIN_ENC_B;
  cb.level_gpio_num = PIN_ENC_A;
  pcnt_channel_handle_t chB;
  pcnt_new_channel(encUnit, &cb, &chB);

  pcnt_channel_set_edge_action(chA, PCNT_CHANNEL_EDGE_ACTION_DECREASE, PCNT_CHANNEL_EDGE_ACTION_INCREASE);
  pcnt_channel_set_level_action(chA, PCNT_CHANNEL_LEVEL_ACTION_KEEP, PCNT_CHANNEL_LEVEL_ACTION_INVERSE);
  pcnt_channel_set_edge_action(chB, PCNT_CHANNEL_EDGE_ACTION_INCREASE, PCNT_CHANNEL_EDGE_ACTION_DECREASE);
  pcnt_channel_set_level_action(chB, PCNT_CHANNEL_LEVEL_ACTION_KEEP, PCNT_CHANNEL_LEVEL_ACTION_INVERSE);

  pcnt_unit_enable(encUnit);
  pcnt_unit_clear_count(encUnit);
  pcnt_unit_start(encUnit);
  return true;
}

/** Сколько щелчков сделала ручка с прошлого вызова (со знаком). */
int readEncoder() {
  if (!encUnit) return 0;
  int count = 0;
  pcnt_unit_get_count(encUnit, &count);
  int steps = (count - encConsumed) / ENC_STEPS_PER_DETENT;
  encConsumed += steps * ENC_STEPS_PER_DETENT;
  // Держим счётчик далеко от предела: сбрасываем, когда ручка стоит ровно на щелчке.
  if (count == encConsumed && abs(encConsumed) > 4000) {
    pcnt_unit_clear_count(encUnit);
    encConsumed = 0;
  }
  return steps * ENC_DIR;
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
  pinSet     = prefs.getBytes("pinh", pinHash, sizeof pinHash) == sizeof pinHash;
  pinFails   = prefs.getUChar("fails", 0);
  tzMinutes  = prefs.getShort("tz", 0);
  brightness = constrain(prefs.getUChar("bright", 7), 1, BRIGHTNESS_LEVELS);
  sleepIdx   = min<uint8_t>(prefs.getUChar("sleep", 2), SLEEP_OPTION_COUNT - 1);
  flipped    = prefs.getBool("flip", false);
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

// ---------------------------------------------------------------- экран: общие функции
void applyDisplaySettings() {
  // SH1106 почти не меняет яркость по контрасту в нижней половине — берём рабочий диапазон.
  u8g2.setContrast(map(brightness, 1, BRIGHTNESS_LEVELS, 1, 255));
  u8g2.setFlipMode(flipped ? 1 : 0);
}

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

void drawHeader(const char* title) {
  u8g2.setFont(u8g2_font_6x12_t_cyrillic);
  u8g2.drawUTF8(0, 10, title);
  u8g2.drawHLine(0, 13, 128);
}

void formatLocalTime(uint32_t t, char* out, size_t n) {
  DateTime local(t + (int32_t)tzMinutes * 60);
  snprintf(out, n, "%02d:%02d:%02d", local.hour(), local.minute(), local.second());
}

/**
 * Список из rows строк под заголовком: 4 видимые строки, выделение инверсией,
 * прокрутка и полоса прокрутки справа. value(i) — необязательное значение справа.
 */
void drawList(const char* title, uint8_t count, uint8_t cursor,
              const char* (*label)(uint8_t), const char* (*value)(uint8_t), bool editing) {
  u8g2.clearBuffer();
  drawHeader(title);
  const uint8_t VISIBLE = 4, ROW_H = 12, TOP = 15;
  uint8_t first = cursor < VISIBLE ? 0 : cursor - VISIBLE + 1;
  bool scroll = count > VISIBLE;
  int width = scroll ? 124 : 128;

  for (uint8_t r = 0; r < VISIBLE && first + r < count; r++) {
    uint8_t i = first + r;
    int y = TOP + r * ROW_H;
    bool sel = i == cursor;
    if (sel) {
      u8g2.setDrawColor(1);
      u8g2.drawBox(0, y, width, ROW_H);
      u8g2.setDrawColor(0);
    }
    // Длинные имена обрезаются по ширине строки, чтобы не залезать на значение и полосу прокрутки
    u8g2.setClipWindow(0, y, width - 2, y + ROW_H);
    u8g2.drawUTF8(3, y + 10, label(i));
    u8g2.setMaxClipWindow();
    if (value) {
      const char* v = value(i);
      if (v && *v) {
        char buf[24];
        snprintf(buf, sizeof buf, sel && editing ? "< %s >" : "%s", v);
        u8g2.drawUTF8(width - 3 - u8g2.getUTF8Width(buf), y + 10, buf);
      }
    }
    u8g2.setDrawColor(1);
  }
  if (scroll) {
    int track = VISIBLE * ROW_H;
    int knob = max(6, track * VISIBLE / count);
    int pos = (track - knob) * cursor / (count - 1);
    u8g2.drawVLine(126, TOP, track);
    u8g2.drawBox(125, TOP + pos, 3, knob);
  }
  u8g2.sendBuffer();
}

// ---------------------------------------------------------------- экран: коды
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

void drawStatusLine(uint32_t t, uint8_t period) {
  u8g2.setFont(u8g2_font_6x12_t_cyrillic);
  if (!timeValid(t)) return;
  if (period) {
    char s[8];
    snprintf(s, sizeof s, "%2us", (unsigned)(period - t % period));
    u8g2.drawStr(0, 63, s);
  }
  char c[12];
  formatLocalTime(t, c, sizeof c);
  u8g2.drawStr(128 - u8g2.getStrWidth(c), 63, c);
}

void drawCodeScreen() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x12_t_cyrillic);
  uint32_t t = nowUtc();

  if (accountCount == 0) {
    drawCentered(14, "Нет аккаунтов");
    drawCentered(32, "Подключите USB:");
    drawCentered(44, "token_cli или Android");
    drawStatusLine(t, 0);
    u8g2.sendBuffer();
    return;
  }

  const Account& a = accounts[current];
  char hdr[48];
  snprintf(hdr, sizeof hdr, "%u/%u %s", current + 1, accountCount, a.name);
  drawHeader(hdr);

  if (!timeValid(t)) {
    drawCentered(32, "Время не задано");
    drawCentered(46, "синхронизируйте по USB");
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

// ---------------------------------------------------------------- экран: список аккаунтов
const char* accountLabel(uint8_t i) { return accounts[i].name; }

void drawAccountList() {
  char title[32];
  snprintf(title, sizeof title, "Аккаунты %u/%u", accountCount, MAX_ACCOUNTS);
  drawList(title, accountCount, listCursor, accountLabel, nullptr, false);
}

// ---------------------------------------------------------------- экран: меню
enum MenuItem { MI_ACCOUNTS, MI_BRIGHTNESS, MI_SLEEP, MI_FLIP, MI_ABOUT, MI_LOCK, MI_COUNT };

const char* menuLabel(uint8_t i) {
  static const char* L[] = {"Аккаунты", "Яркость", "Автосон", "Поворот", "О токене", "Заблокировать"};
  return i < MI_COUNT ? L[i] : "";
}

const char* menuValue(uint8_t i) {
  static char buf[12];
  switch (i) {
    case MI_BRIGHTNESS: snprintf(buf, sizeof buf, "%u/%u", brightness, BRIGHTNESS_LEVELS); return buf;
    case MI_SLEEP:
      if (SLEEP_OPTIONS[sleepIdx] < 60) snprintf(buf, sizeof buf, "%u с", SLEEP_OPTIONS[sleepIdx]);
      else snprintf(buf, sizeof buf, "%u мин", SLEEP_OPTIONS[sleepIdx] / 60);
      return buf;
    case MI_FLIP: return flipped ? "180°" : "нет";
    default: return "";
  }
}

void drawMenu() { drawList("Меню", MI_COUNT, menuCursor, menuLabel, menuValue, menuEditing); }

// ---------------------------------------------------------------- экран: о токене
void drawAbout() {
  u8g2.clearBuffer();
  drawHeader("О токене");
  char line[40];
  uint32_t t = nowUtc();

  snprintf(line, sizeof line, "Прошивка  v%s", FW_VERSION);
  u8g2.drawUTF8(0, 26, line);
  snprintf(line, sizeof line, "Аккаунты  %u из %u", accountCount, MAX_ACCOUNTS);
  u8g2.drawUTF8(0, 38, line);
  snprintf(line, sizeof line, "PIN       %s", pinSet ? "установлен" : "не задан");
  u8g2.drawUTF8(0, 50, line);
  if (!rtcOk)              snprintf(line, sizeof line, "Часы      нет DS3231");
  else if (!timeValid(t))  snprintf(line, sizeof line, "Часы      не заданы");
  else {
    char c[12];
    formatLocalTime(t, c, sizeof c);
    snprintf(line, sizeof line, "Часы      %s", c);
  }
  u8g2.drawUTF8(0, 62, line);
  u8g2.sendBuffer();
}

// ---------------------------------------------------------------- экран: PIN
void drawPin() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x12_t_cyrillic);
  drawCentered(10, "Введите PIN");

  for (uint8_t i = 0; i < PIN_LEN; i++) {
    int x = 14 + i * 26;
    if (i < pinPos) {
      u8g2.drawDisc(x + 8, 32, 5);
    } else if (i == pinPos) {
      u8g2.setFont(u8g2_font_logisoso20_tn);
      char d[2] = {(char)('0' + pinEntry[i]), 0};
      u8g2.drawStr(x + 2, 42, d);
      u8g2.drawFrame(x - 2, 16, 22, 30);
      u8g2.setFont(u8g2_font_6x12_t_cyrillic);
    } else {
      u8g2.drawHLine(x, 42, 16);
    }
  }

  if (pinFails > 0) {
    char s[32];
    snprintf(s, sizeof s, "Осталось попыток: %u", MAX_PIN_FAILS - pinFails);
    drawCentered(62, s);
  } else {
    drawCentered(62, "Крутите ручку, OK");
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
    case SCR_CODE:    drawCodeScreen(); break;
    case SCR_LIST:    drawAccountList(); break;
    case SCR_MENU:    drawMenu(); break;
    case SCR_ABOUT:   drawAbout(); break;
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
  menuEditing = false;
  screen = pinSet ? SCR_PIN : SCR_CODE;
  resetPinEntry();
}

void goToSleep() {
  u8g2.setPowerSave(1);
  Serial.flush();

  // Ждём отпускания кнопок, иначе устройство сразу проснётся.
  while (anyButtonDown()) delay(10);
  delay(50);

  const uint8_t pins[] = {PIN_CON, PIN_BAK, PIN_PSH};
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

void lockAndSleep() {
  lockDevice();
  if (usbHostConnected()) {
    // Подключены к компьютеру или телефону — не засыпаем (иначе пропадёт порт), только гасим экран.
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

void fixCursors() {
  if (current >= accountCount) current = accountCount ? accountCount - 1 : 0;
  if (listCursor >= accountCount) listCursor = accountCount ? accountCount - 1 : 0;
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
    else if (r == PIN_WIPED) { screen = SCR_CODE; reply(false, "too many attempts, device wiped"); }
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
    fixCursors();
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
    screen = SCR_CODE;
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
      if (screen != SCR_PIN && screen != SCR_MESSAGE && displayOn) redraw();
    } else if (serialLine.length() < 300) {
      serialLine += c;
    }
  }
}

// ---------------------------------------------------------------- управление
// Ручка: поворот — навигация; нажатие ручки и CONFIRM работают одинаково.
struct Input {
  int  turn;      // щелчки ручки (+ по часовой)
  bool ok;        // короткое нажатие CONFIRM или ручки
  bool okLong;    // удержание CONFIRM или ручки
  bool back;      // короткое нажатие BACK
  bool backLong;  // удержание BACK
  bool any() const { return turn || ok || okLong || back || backLong; }
};

int wrap(int v, int n) { return ((v % n) + n) % n; }

void handlePinScreen(const Input& in) {
  if (in.turn) pinEntry[pinPos] = wrap(pinEntry[pinPos] + in.turn, 10);
  if (in.back && pinPos > 0) { pinPos--; return; }
  if (!in.ok) return;

  if (++pinPos < PIN_LEN) { pinEntry[pinPos] = 0; return; }

  char p[PIN_LEN + 1];
  for (uint8_t i = 0; i < PIN_LEN; i++) p[i] = '0' + pinEntry[i];
  p[PIN_LEN] = 0;
  resetPinEntry();

  showMessage("Проверка...", 0, SCR_PIN);
  redraw();
  PinResult r = verifyPin(p);
  memset(p, 0, sizeof p);

  if (r == PIN_OK)         { screen = SCR_CODE; }
  else if (r == PIN_WIPED) { showMessage("Данные стёрты", 3000, SCR_CODE); }
  else                     { showMessage("Неверный PIN", 1500, SCR_PIN); }
}

void handleCodeScreen(const Input& in) {
  if (accountCount > 0 && in.turn) current = wrap(current + in.turn, accountCount);
  if (in.ok && accountCount > 0) { listCursor = current; screen = SCR_LIST; }
  if (in.okLong) { menuCursor = 0; menuEditing = false; screen = SCR_MENU; }
  if (in.back) lockAndSleep();
}

void handleListScreen(const Input& in) {
  if (accountCount == 0 || in.back) { screen = SCR_CODE; return; }
  if (in.turn) listCursor = constrain((int)listCursor + in.turn, 0, accountCount - 1);
  if (in.ok) { current = listCursor; screen = SCR_CODE; }
}

void saveSettings() {
  prefs.putUChar("bright", brightness);
  prefs.putUChar("sleep", sleepIdx);
  prefs.putBool("flip", flipped);
}

void handleMenuScreen(const Input& in) {
  if (menuEditing) {
    if (in.turn) {
      if (menuCursor == MI_BRIGHTNESS) brightness = constrain((int)brightness + in.turn, 1, BRIGHTNESS_LEVELS);
      if (menuCursor == MI_SLEEP)      sleepIdx = constrain((int)sleepIdx + in.turn, 0, SLEEP_OPTION_COUNT - 1);
      applyDisplaySettings();
    }
    if (in.ok || in.back) { menuEditing = false; saveSettings(); }
    return;
  }

  if (in.back) { screen = SCR_CODE; return; }
  if (in.turn) menuCursor = constrain((int)menuCursor + in.turn, 0, MI_COUNT - 1);
  if (!in.ok) return;

  switch (menuCursor) {
    case MI_ACCOUNTS:
      if (accountCount) { listCursor = current; screen = SCR_LIST; }
      else showMessage("Аккаунтов нет", 1200, SCR_MENU);
      break;
    case MI_BRIGHTNESS:
    case MI_SLEEP:
      menuEditing = true;
      break;
    case MI_FLIP:
      flipped = !flipped;
      applyDisplaySettings();
      saveSettings();
      break;
    case MI_ABOUT:
      screen = SCR_ABOUT;
      break;
    case MI_LOCK:
      lockAndSleep();
      break;
  }
}

// ---------------------------------------------------------------- setup / loop
void setup() {
  Serial.begin(115200);

  initButton(bCon);
  initButton(bBak);
  initButton(bPsh);
  initEncoder();

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
  applyDisplaySettings();

  resetPinEntry();
  screen = pinSet ? SCR_PIN : SCR_CODE;
  if (!rtcOk) showMessage("DS3231 не найден", 2000, screen);
  else if (rtcLost) showMessage("RTC сброшен!", 2000, screen);

  lastActivity = millis();
  redraw();
}

void loop() {
  handleSerial();

  Ev con = pollButton(bCon);
  Ev psh = pollButton(bPsh);
  Ev bak = pollButton(bBak);
  Input in;
  in.turn     = readEncoder();
  in.ok       = con == EV_SHORT || psh == EV_SHORT;
  in.okLong   = con == EV_LONG  || psh == EV_LONG;
  in.back     = bak == EV_SHORT;
  in.backLong = bak == EV_LONG;

  uint32_t now = millis();
  bool any = in.any();
  if (any) lastActivity = now;

  if (!displayOn) {
    if (any) {  // первое действие только будит экран
      displayOn = true;
      u8g2.setPowerSave(0);
      redraw();
    }
    delay(5);
    return;
  }

  switch (screen) {
    case SCR_PIN:   if (any) handlePinScreen(in); break;
    case SCR_CODE:  if (any) handleCodeScreen(in); break;
    case SCR_LIST:  if (any) handleListScreen(in); break;
    case SCR_MENU:  if (any) handleMenuScreen(in); break;
    case SCR_ABOUT: if (in.back || in.ok) screen = SCR_MENU; break;
    case SCR_MESSAGE:
      if ((int32_t)(now - messageUntil) >= 0) screen = afterMessage;
      break;
  }

  if (displayOn && (any || now - lastRedraw > 200)) redraw();

  if (displayOn && now - lastActivity > SLEEP_OPTIONS[sleepIdx] * 1000UL) lockAndSleep();

  delay(5);
}
