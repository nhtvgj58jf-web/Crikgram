#!/usr/bin/env python3
"""Подмена сервера и ID приложения в клиентах Android / tdesktop.
Env: SERVER_IP, RSA_PUBLIC_PEM (любой формат PEM), APP_PACKAGE, APP_NAME
Запуск: python patch_client.py android|desktop <папка исходников>"""
import os, re, sys, hashlib, uuid, pathlib
from cryptography.hazmat.primitives import serialization

OLD_IP = "192.168.1.100"
OLD_FP = "0xce27f5081215bda4"  # отпечаток ключа авторов (Android Handshake.cpp)

def die(m): print("ОШИБКА:", m); sys.exit(1)

def load_key():
    pem = os.environ.get("RSA_PUBLIC_PEM", "").strip().encode()
    if not pem: die("RSA_PUBLIC_PEM пуст")
    try: k = serialization.load_pem_public_key(pem)
    except Exception:
        k = serialization.load_pem_private_key(pem, None).public_key()
    return k

def pkcs1(k):
    return k.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1).decode().strip()

def tl_bytes(b):
    h = bytes([len(b)]) if len(b) < 254 else b"\xfe" + len(b).to_bytes(3, "little")
    r = h + b
    return r + b"\0" * (-len(r) % 4)

def fingerprint(k):
    n = k.public_numbers()
    nb = n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")
    eb = n.e.to_bytes((n.e.bit_length() + 7) // 8, "big")
    d = hashlib.sha1(tl_bytes(nb) + tl_bytes(eb)).digest()
    return "0x%016x" % int.from_bytes(d[-8:], "little")

def c_literal(pem):
    return " ".join('"%s\\n"' % l for l in pem.splitlines())

PEM_RE = r'"-----BEGIN (?:RSA )?PUBLIC KEY-----.*?-----END (?:RSA )?PUBLIC KEY-----(?:\\n)?"'
RAW_RE = r'R"\(-----BEGIN (?:RSA )?PUBLIC KEY-----.*?-----END (?:RSA )?PUBLIC KEY-----\s*\)"'

def edit(path, fn):
    p = pathlib.Path(path)
    if not p.exists(): die("нет файла " + path)
    s = p.read_text(encoding="utf-8", errors="ignore"); n = fn(s)
    if n == s: die("ничего не изменилось в " + path)
    p.write_text(n, encoding="utf-8"); print("OK", path)

def find(root, name):
    r = list(pathlib.Path(root).rglob(name))
    if not r: die("не найден " + name)
    return r[0]

def sub_all_ip(root, exts):
    ip = os.environ.get("SERVER_IP", "").strip()
    if not ip: die("SERVER_IP пуст")
    c = 0
    for p in pathlib.Path(root).rglob("*"):
        if p.suffix in exts and p.is_file() and ".git" not in p.parts:
            s = p.read_text(encoding="utf-8", errors="ignore")
            if OLD_IP in s:
                p.write_text(s.replace(OLD_IP, ip), encoding="utf-8"); c += 1; print("IP", p)
    if not c: die("заглушка IP не найдена")


def add_client(path, pkg):
    """Добавляет в google-services.json клиента с новым id, СТАРЫЕ оставляет:
    модули Gradle могут искать любой из двух пакетов."""
    import json, copy
    d = json.loads(path.read_text(encoding="utf-8"))
    have = {c["client_info"]["android_client_info"]["package_name"] for c in d.get("client", [])}
    if pkg in have: print("OK (уже есть)", path); return
    for c in list(d.get("client", [])):
        n = copy.deepcopy(c)
        n["client_info"]["android_client_info"]["package_name"] = pkg
        d["client"].append(n); break
    path.write_text(json.dumps(d, indent=2), encoding="utf-8"); print("OK", path, "пакеты:", sorted(have | {pkg}))

def android(root):
    k = load_key(); pem = pkcs1(k); fp = fingerprint(k)
    pkg = os.environ.get("APP_PACKAGE", "").strip()
    name = os.environ.get("APP_NAME", "").strip()
    if not re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+", pkg): die("APP_PACKAGE некорректен: " + pkg)
    sub_all_ip(root + "/TMessagesProj/jni", {".cpp", ".h"})
    for f in ("Datacenter.cpp", "Handshake.cpp"):
        edit(find(root, f), lambda s: re.sub(PEM_RE, lambda m: c_literal(pem), s, flags=re.S))
    edit(find(root, "Handshake.cpp"), lambda s: re.sub(re.escape(OLD_FP), fp, s, flags=re.I))
    for gp in pathlib.Path(root).rglob("gradle.properties"):
        s = gp.read_text()
        if "APP_PACKAGE" in s:
            gp.write_text(re.sub(r"^APP_PACKAGE\s*=.*$", "APP_PACKAGE=" + pkg, s, flags=re.M)); print("OK", gp)
    for gj in pathlib.Path(root).rglob("google-services.json"):
        add_client(gj, pkg)
    for bg in pathlib.Path(root).rglob("build.gradle*"):  # диагностика: где задан applicationId
        for i, l in enumerate(bg.read_text(errors="ignore").splitlines(), 1):
            if "applicationId" in l or "APP_PACKAGE" in l: print("APPID", bg, i, l.strip()[:120])
    if name:
        for x in pathlib.Path(root).rglob("strings*.xml"):
            s = x.read_text(encoding="utf-8", errors="ignore")
            n = re.sub(r'(<string name="AppName"[^>]*>)[^<]*', lambda m: m.group(1) + name, s)
            if n != s: x.write_text(n, encoding="utf-8"); print("OK", x)
    print("Отпечаток:", fp)

def desktop(root):
    k = load_key(); pem = pkcs1(k)
    name = os.environ.get("APP_NAME", "").strip()
    pkg = os.environ.get("APP_PACKAGE", "").strip()
    sub_all_ip(root + "/Telegram/SourceFiles/mtproto", {".cpp", ".h"})
    edit(find(root, "mtproto_dc_options.cpp"),
         lambda s: re.sub(RAW_RE, lambda m: 'R"(' + pem + '\n)"', s, flags=re.S))
    v = pathlib.Path(find(root, "version.h"))
    s = v.read_text(); n = s
    if pkg:  # свой GUID установщика/приложения, детерминированный
        g = "{%s}" % str(uuid.uuid5(uuid.NAMESPACE_DNS, pkg)).upper()
        n = re.sub(r'(AppId\s*=\s*)"\{[0-9A-Fa-f-]+\}"', r'\1"%s"' % g, n)
    if name:  # от имени зависит папка данных (tdata) и блокировка второго экземпляра
        n = re.sub(r'(AppName\s*=\s*)"[^"]*"', r'\1"%s"' % name, n)
    if n == s: print("ВНИМАНИЕ: version.h не изменился (AppId/AppName не найдены)")
    else: v.write_text(n); print("OK", v)

if __name__ == "__main__":
    if len(sys.argv) != 3: die(__doc__)
    {"android": android, "desktop": desktop}[sys.argv[1]](sys.argv[2])
    left = [p for p in pathlib.Path(sys.argv[2]).rglob("*.cpp") if OLD_IP in p.read_text(errors="ignore")]
    if left: die("осталась заглушка IP: %s" % left)
