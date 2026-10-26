#!/usr/bin/env python3
"""Утилита настройки TOTP-токена на ESP32-C6 через USB.

Примеры:
  python token_cli.py sync
  python token_cli.py setpin
  python token_cli.py add "otpauth://totp/GitHub:artem?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
  python token_cli.py add "otpauth-migration://offline?data=..."   # экспорт из Google Authenticator
  python token_cli.py add-manual --name "Yandex" --secret JBSWY3DPEHPK3PXP
  python token_cli.py list
  python token_cli.py del 2
  python token_cli.py tz 7
"""
import argparse
import base64
import getpass
import sys
import time
from urllib.parse import parse_qs, unquote, urlparse

import serial
from serial.tools import list_ports

ESPRESSIF_VID = 0x303A
ALGOS = ("SHA1", "SHA256", "SHA512")


class DeviceError(Exception):
    pass


class Token:
    def __init__(self, port, pin=None):
        self.ser = serial.Serial(port, 115200, timeout=8)
        time.sleep(0.3)
        self.ser.reset_input_buffer()
        self.pin = pin
        self.ser.write(b"\n")  # сбросить возможную недописанную строку
        time.sleep(0.1)
        self.ser.reset_input_buffer()

    def cmd(self, line):
        self.ser.write((line + "\n").encode("utf-8"))
        out = []
        while True:
            raw = self.ser.readline()
            if not raw:
                raise DeviceError("нет ответа от устройства (нажмите кнопку, чтобы разбудить)")
            s = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if s == "OK":
                return out
            if s.startswith("ERR"):
                raise DeviceError(s[4:])
            out.append(s)

    def info(self):
        return dict(l.split("=", 1) for l in self.cmd("info") if "=" in l)

    def authenticate(self):
        if self.info().get("auth") == "1":
            return
        pin = self.pin or getpass.getpass("PIN токена: ")
        self.cmd(f"auth {pin}")


def find_port():
    ports = [p for p in list_ports.comports() if p.vid == ESPRESSIF_VID]
    if not ports:
        sys.exit("Токен не найден. Укажите порт вручную: --port COM5 / --port /dev/ttyACM0")
    return ports[0].device


def truncate_utf8(s, limit=31):
    return s.encode("utf-8")[:limit].decode("utf-8", errors="ignore").strip()


# ------------------------------------------------------------------ разбор otpauth://
def parse_otpauth(uri):
    u = urlparse(uri)
    if u.netloc.lower() != "totp":
        raise ValueError("поддерживается только TOTP (не HOTP)")
    label = unquote(u.path.lstrip("/"))
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    if "secret" not in q:
        raise ValueError("в URI нет параметра secret")
    issuer = q.get("issuer", "")
    name = label
    if issuer and not label.lower().startswith(issuer.lower()):
        name = f"{issuer}:{label}"
    return [{
        "name": name,
        "secret": q["secret"].replace(" ", "").upper().rstrip("="),
        "digits": int(q.get("digits", 6)),
        "period": int(q.get("period", 30)),
        "algo": q.get("algorithm", "SHA1").upper(),
    }]


# ------------------------------------------------------------------ экспорт Google Authenticator
def _varint(buf, i):
    shift = result = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def _fields(buf):
    i = 0
    while i < len(buf):
        key, i = _varint(buf, i)
        field, wire = key >> 3, key & 7
        if wire == 0:
            val, i = _varint(buf, i)
        elif wire == 2:
            ln, i = _varint(buf, i)
            val, i = buf[i:i + ln], i + ln
        elif wire == 1:
            val, i = buf[i:i + 8], i + 8
        elif wire == 5:
            val, i = buf[i:i + 4], i + 4
        else:
            raise ValueError("повреждённые данные экспорта")
        yield field, val


def parse_migration(uri):
    raw = uri.split("data=", 1)[1].split("&", 1)[0]
    data = unquote(raw)  # не parse_qs: он превращает '+' в пробел
    data += "=" * (-len(data) % 4)
    payload = base64.b64decode(data)
    result = []
    for field, val in _fields(payload):
        if field != 1:
            continue
        p = dict(_fields(val))
        if p.get(6, 2) != 2:
            print(f"  пропуск HOTP: {p.get(2, b'').decode()}")
            continue
        algo = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512"}.get(p.get(4, 0))
        if algo is None:
            print(f"  пропуск (MD5 не поддерживается): {p.get(2, b'').decode()}")
            continue
        name = p.get(2, b"").decode("utf-8")
        issuer = p.get(3, b"").decode("utf-8")
        if issuer and not name.lower().startswith(issuer.lower()):
            name = f"{issuer}:{name}"
        result.append({
            "name": name,
            "secret": base64.b32encode(p[1]).decode().rstrip("="),
            "digits": 8 if p.get(5, 1) == 2 else 6,
            "period": 30,
            "algo": algo,
        })
    return result


def parse_uri(uri):
    if uri.startswith("otpauth-migration://"):
        return parse_migration(uri)
    if uri.startswith("otpauth://"):
        return parse_otpauth(uri)
    raise ValueError("ожидается otpauth:// или otpauth-migration://")


def push_account(tok, acc):
    if acc["algo"] not in ALGOS:
        raise ValueError(f"алгоритм {acc['algo']} не поддерживается")
    name = truncate_utf8(acc["name"].replace("\n", " "))
    tok.cmd(f"add {acc['secret']} {acc['digits']} {acc['period']} {acc['algo']} {name}")
    print(f"  + {name}  ({acc['digits']} цифр, {acc['period']} с, {acc['algo']})")


# ------------------------------------------------------------------ команды
def main():
    ap = argparse.ArgumentParser(description="Настройка TOTP-токена ESP32-C6")
    ap.add_argument("--port", help="COM-порт (по умолчанию ищется автоматически)")
    ap.add_argument("--pin", help="PIN токена (иначе будет запрошен)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("info", help="состояние токена")
    sub.add_parser("sync", help="синхронизировать время с компьютером")
    sub.add_parser("list", help="список аккаунтов")
    sub.add_parser("selftest", help="проверка алгоритма по RFC 6238")

    p = sub.add_parser("add", help="добавить из otpauth:// или otpauth-migration://")
    p.add_argument("uri", nargs="+")

    p = sub.add_parser("add-manual", help="добавить вручную")
    p.add_argument("--name", required=True)
    p.add_argument("--secret", required=True, help="секрет в Base32")
    p.add_argument("--digits", type=int, default=6)
    p.add_argument("--period", type=int, default=30)
    p.add_argument("--algo", default="SHA1", choices=ALGOS)

    p = sub.add_parser("del", help="удалить аккаунт")
    p.add_argument("index", type=int)

    p = sub.add_parser("move", help="переместить аккаунт")
    p.add_argument("src", type=int)
    p.add_argument("dst", type=int)

    p = sub.add_parser("tz", help="часовой пояс для часов на экране, в часах (напр. 7 или 5.5)")
    p.add_argument("hours", type=float)

    p = sub.add_parser("setpin", help="задать PIN (4 цифры) или 'off'")
    p.add_argument("value", nargs="?")

    sub.add_parser("wipe", help="стереть всё")

    a = ap.parse_args()
    tok = Token(a.port or find_port(), a.pin)

    try:
        if a.cmd == "info":
            for k, v in tok.info().items():
                print(f"{k:10} {v}")
            return

        tok.authenticate()

        if a.cmd == "sync":
            frac = time.time() % 1
            time.sleep(1 - frac)  # отправляем ровно на границе секунды
            tok.cmd(f"time {int(round(time.time()))}")
            dev = int(tok.info()["time"])
            print(f"Время установлено, расхождение: {dev - int(time.time())} с")

        elif a.cmd == "list":
            rows = tok.cmd("list")
            if not rows:
                print("Аккаунтов нет")
            for r in rows:
                i, name, digits, period, algo = r.split("|")
                print(f"{i:>2}. {name:32} {digits} цифр  {period} с  {algo}")

        elif a.cmd == "add":
            for uri in a.uri:
                for acc in parse_uri(uri):
                    push_account(tok, acc)

        elif a.cmd == "add-manual":
            push_account(tok, {
                "name": a.name, "secret": a.secret.replace(" ", "").upper().rstrip("="),
                "digits": a.digits, "period": a.period, "algo": a.algo,
            })

        elif a.cmd == "del":
            tok.cmd(f"del {a.index}")
            print("Удалено")

        elif a.cmd == "move":
            tok.cmd(f"move {a.src} {a.dst}")
            print("Перемещено")

        elif a.cmd == "tz":
            tok.cmd(f"tz {int(round(a.hours * 60))}")
            print("Часовой пояс сохранён")

        elif a.cmd == "setpin":
            value = a.value
            if value is None:
                value = getpass.getpass("Новый PIN (4 цифры): ")
                if value != getpass.getpass("Повторите PIN: "):
                    sys.exit("PIN не совпадает")
            tok.cmd(f"setpin {value}")
            print("PIN снят" if value == "off" else "PIN установлен")

        elif a.cmd == "selftest":
            for line in tok.cmd("selftest"):
                print(line)
            print("Все тесты пройдены")

        elif a.cmd == "wipe":
            if input("Стереть ВСЕ аккаунты и PIN? Введите YES: ") == "YES":
                tok.cmd("wipe YES")
                print("Токен очищен")

    except (DeviceError, ValueError) as e:
        sys.exit(f"Ошибка: {e}")


if __name__ == "__main__":
    main()
