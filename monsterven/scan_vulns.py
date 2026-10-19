#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_vulns.py — автоматический SAST(+DAST)-анализ проекта и построение датасета
уязвимостей с корреляцией CWE / OWASP / CVSS / CVE (практика №2, РБПО).

Что делает:
  1. Находит в каталоге проекта файлы Python / C++ / JavaScript / шаблоны.
  2. Запускает сканеры:
        Bandit      — Python
        Cppcheck    — C/C++
        Flawfinder  — C/C++ (ловит strcpy/printf/system, которые Cppcheck пропускает)
        ESLint + eslint-plugin-security — JavaScript
        Semgrep     — все языки, с КАСТОМНЫМИ правилами (SQLi/XSS/IDOR/слабая
                      аутентификация/|safe), работают офлайн
        OWASP ZAP   — DAST (опционально, через Docker, --zap-url)
  3. Приводит результаты к единому формату, объединяет дубли (один и тот же дефект,
     найденный несколькими сканерами, — одна строка).
  4. Сопоставляет каждую находку с CWE → OWASP Top 10 → CVSS → пример CVE.
  5. Пишет: vulnerabilities.csv/json, cwe_mapping.csv, expert_assessment.md
     и «сырые» отчёты сканеров в reports/.

Примеры:
    python3 scan_vulns.py ./vulnmart
    python3 scan_vulns.py ./vulnmart --out ./vuln_dataset --zap-url http://127.0.0.1:5055
    python3 scan_vulns.py ./vulnmart --skip eslint,zap

Использовать ТОЛЬКО на своём учебном коде / своих локальных стендах.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
#  Справочные таблицы (CWE → название, OWASP, CVSS, описание, рекомендация)   #
# --------------------------------------------------------------------------- #
# CVSS ниже — ЭКСПЕРТНЫЕ ОЦЕНКИ для типового случая (как в датасете практики),
# а не рассчитанные по вектору значения. При необходимости правьте вручную.

OWASP_NAMES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}


def _c(name, owasp, cvss, impact, desc, rec):
    return dict(name=name, owasp=owasp, cvss=cvss, impact=impact, desc=desc, rec=rec)


CWE_INFO: dict[int, dict] = {
    89: _c("SQL Injection", "A03", 9.8,
           "Утечка данных, обход аутентификации",
           "Пользовательский ввод попадает в SQL-запрос без параметризации",
           "Параметризованные запросы (placeholder ?), ORM; никогда не конкатенировать ввод в SQL."),
    79: _c("Cross-site Scripting (XSS)", "A03", 8.2,
           "Захват сессии, кража данных",
           "Пользовательский ввод выводится в HTML без экранирования",
           "Контекстное экранирование вывода (autoescape без |safe), строгий CSP, санитайзер для HTML."),
    78: _c("OS Command Injection", "A03", 9.8,
           "Удалённое выполнение кода",
           "Пользовательский ввод попадает в системную команду",
           "Не вызывать shell: execFile/spawn без shell (JS), subprocess.run([...]) (Python); белый список аргументов."),
    120: _c("Buffer Overflow (Classic)", "A06", 9.5,
            "Удалённое выполнение кода",
            "Копирование в буфер фиксированного размера без проверки длины",
            "std::string / snprintf / strncpy с явным '\\0'; проверка длины; -fstack-protector, ASan."),
    119: _c("Improper Restriction of Operations within Memory Buffer", "A06", 9.0,
            "Повреждение памяти, RCE",
            "Операция с памятью выходит за границы буфера",
            "Проверка границ, безопасные контейнеры (std::vector/std::string/std::span), санитайзеры."),
    121: _c("Stack-based Buffer Overflow", "A06", 9.5,
            "Удалённое выполнение кода", "Переполнение буфера на стеке",
            "Проверка длины, std::string, защитные флаги компилятора."),
    122: _c("Heap-based Buffer Overflow", "A06", 9.5,
            "Удалённое выполнение кода", "Переполнение буфера в куче",
            "Проверка длины, std::vector/std::string, санитайзеры."),
    125: _c("Out-of-bounds Read", "A06", 7.5,
            "Утечка памяти процесса, DoS", "Чтение за границами буфера",
            "Проверка индексов и размеров, безопасные контейнеры."),
    787: _c("Out-of-bounds Write", "A06", 9.0,
            "Повреждение памяти, RCE", "Запись за границами буфера",
            "Проверка индексов и размеров, безопасные контейнеры."),
    788: _c("Access of Memory Location After End of Buffer", "A06", 8.0,
            "Повреждение памяти", "Доступ к памяти после конца буфера",
            "Проверка границ, безопасные контейнеры."),
    134: _c("Format String", "A03", 7.8,
            "Утечка информации, выполнение кода",
            "printf-подобная функция получает управляемую пользователем строку формата",
            "Фиксированная строка формата: printf(\"%s\", input); -Wformat-security."),
    476: _c("NULL Pointer Dereference", "A05", 5.5,
            "Отказ в обслуживании", "Разыменование указателя, который может быть NULL",
            "Проверять указатели/результаты функций на nullptr; использовать ссылки и умные указатели."),
    416: _c("Use After Free", "A06", 8.8, "RCE, повреждение памяти",
            "Обращение к освобождённой памяти", "Умные указатели (RAII), ASan."),
    401: _c("Memory Leak", "A06", 5.3, "Исчерпание памяти (DoS)",
            "Память не освобождается", "RAII, умные указатели."),
    190: _c("Integer Overflow", "A06", 7.5, "Некорректные размеры буферов, RCE",
            "Арифметическое переполнение целого", "Проверка диапазонов перед арифметикой."),
    639: _c("IDOR (Authorization Bypass Through User-Controlled Key)", "A01", 6.5,
            "Доступ к чужим данным",
            "Объект выбирается по ID из запроса без проверки владельца",
            "Проверять владельца: WHERE id=? AND user_id=?; политики доступа на уровне объекта."),
    862: _c("Missing Authorization", "A01", 7.5, "Несанкционированный доступ",
            "Отсутствует проверка прав доступа", "Централизованная авторизация (RBAC/ABAC), deny by default."),
    352: _c("Cross-Site Request Forgery", "A01", 6.5, "Действия от имени жертвы",
            "Нет защиты от межсайтовой подделки запроса", "CSRF-токены, SameSite-cookie."),
    22: _c("Path Traversal", "A01", 7.5, "Чтение/запись произвольных файлов",
           "Путь к файлу строится из пользовательского ввода", "Нормализация пути, белый список, chroot."),
    307: _c("Excessive Authentication Attempts (no rate limiting)", "A07", 7.5,
            "Подбор паролей (brute force)",
            "Нет ограничения числа попыток аутентификации",
            "Rate limiting (Flask-Limiter / express-rate-limit), временная блокировка, MFA."),
    256: _c("Plaintext Storage of a Password", "A02", 7.5,
            "Компрометация учётных записей при утечке БД",
            "Пароли хранятся/сравниваются в открытом виде",
            "Хранить только соль+хеш (argon2id / bcrypt / scrypt), сравнивать хеши."),
    259: _c("Use of Hard-coded Password", "A07", 7.5,
            "Компрометация сессий/учётных записей",
            "Пароль/секретный ключ зашит в исходный код",
            "Секреты — из переменных окружения / хранилища секретов; ротация ключей."),
    798: _c("Use of Hard-coded Credentials", "A07", 9.8,
            "Компрометация учётных записей", "Учётные данные зашиты в код",
            "Хранилище секретов, переменные окружения."),
    489: _c("Active Debug Code", "A05", 5.3, "Раскрытие информации / RCE через отладчик",
            "Включён режим отладки", "debug=False в production."),
    95: _c("Eval Injection", "A03", 9.8, "Удалённое выполнение кода",
           "Динамическое выполнение пользовательского ввода (eval)", "Не использовать eval; парсеры/белые списки."),
    327: _c("Broken or Risky Cryptographic Algorithm", "A02", 7.5, "Раскрытие данных",
            "Слабый криптоалгоритм (MD5/SHA1/DES)", "SHA-256+, AES-GCM, argon2/bcrypt для паролей."),
    330: _c("Insufficiently Random Values", "A02", 5.3, "Предсказуемые токены",
            "Небезопасный генератор случайных чисел", "secrets / crypto.randomBytes."),
    502: _c("Deserialization of Untrusted Data", "A08", 9.8, "Удалённое выполнение кода",
            "Десериализация недоверенных данных (pickle/yaml.load)", "JSON, safe_load, подпись данных."),
    918: _c("Server-Side Request Forgery", "A10", 7.5, "Доступ ко внутренним сервисам",
            "Сервер делает запрос по URL из ввода", "Белый список хостов, запрет внутренних адресов."),
    703: _c("Improper Check of Exceptional Conditions", "A04", 3.1, "Обход проверок при assert -O",
            "assert используется для проверок безопасности", "Явные проверки и исключения вместо assert."),
    # --- типичные находки DAST (ZAP) ---
    693: _c("Protection Mechanism Failure (security headers)", "A05", 5.3, "Ослабление защиты браузера",
            "Отсутствуют защитные HTTP-заголовки (CSP и др.)", "Добавить CSP, X-Content-Type-Options и др."),
    1021: _c("Clickjacking (Improper Restriction of Rendered UI Layers)", "A05", 4.3, "Clickjacking",
             "Нет X-Frame-Options / frame-ancestors", "X-Frame-Options: DENY или CSP frame-ancestors."),
    16: _c("Configuration", "A05", 5.3, "Раскрытие информации", "Небезопасная конфигурация",
           "Привести конфигурацию в соответствие с hardening-гайдами."),
    200: _c("Exposure of Sensitive Information", "A01", 5.3, "Утечка информации",
            "Раскрытие чувствительной информации", "Убрать лишние данные из ответов/заголовков."),
    614: _c("Sensitive Cookie Without Secure Flag", "A05", 4.3, "Перехват cookie", "Нет флага Secure",
            "Cookie с Secure."),
    1004: _c("Sensitive Cookie Without HttpOnly Flag", "A05", 4.3, "Кража cookie через XSS", "Нет флага HttpOnly",
             "Cookie с HttpOnly."),
    1275: _c("Sensitive Cookie with Improper SameSite", "A01", 4.3, "CSRF", "Нет атрибута SameSite",
             "SameSite=Lax/Strict."),
}

# Ранги CWE Top 25 2025 — ровно те, что приведены в тексте практики (сверьте с mitre.org!).
RANK_2025 = {79: 1, 89: 2, 78: 9, 120: 11, 476: 14, 122: 16}

# Примеры CVE — взяты из текста практики. ПРОВЕРЬТЕ каждый на nvd.nist.gov перед сдачей.
CVE_EXAMPLES = {
    (89, "JavaScript"): "CVE-2020-37243",
    (89, "*"): "CVE-2019-25676",
    (79, "JavaScript"): "CVE-2005-3309",
    (79, "*"): "CVE-2005-3308",
    (120, "*"): "CVE-2026-89633",
    (78, "*"): "CVE-2026-30880",
    (476, "*"): "CVE-2026-89749",
}

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# --------------------------------------------------------------------------- #
#  Модель данных                                                              #
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    tool: str
    rule_id: str
    file: str            # путь относительно корня проекта (или URL для DAST)
    line: int
    cwe: int | None
    message: str
    severity: str        # low / medium / high  (оценка самого сканера)
    language: str


@dataclass
class ToolStatus:
    name: str
    status: str          # ok / skipped / error
    detail: str = ""
    count: int = 0


EXT_LANG = {
    ".py": "Python", ".html": "Python", ".jinja": "Python", ".jinja2": "Python", ".j2": "Python",
    ".c": "C++", ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".h": "C++", ".hpp": "C++", ".hxx": "C++",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript", ".ts": "JavaScript",
}
EXCLUDE_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build", ".idea", ".vscode"}


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 1200):
    """Запуск внешней команды. None, если программа не найдена."""
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        log(f"  ! таймаут: {' '.join(cmd[:3])}…")
        return None


def first_json(text: str):
    i = text.find("{")
    return json.loads(text[i:]) if i >= 0 else {}


def to_sev(s: str) -> str:
    s = (s or "").lower()
    if s in ("error", "high", "critical", "3"):
        return "high"
    if s in ("warning", "medium", "2"):
        return "medium"
    return "low"


# --------------------------------------------------------------------------- #
#  Контекст сканирования                                                      #
# --------------------------------------------------------------------------- #


class Ctx:
    def __init__(self, root: Path, out: Path):
        self.root = root.resolve()
        self.out = out.resolve()
        self.reports = self.out / "reports"
        self.work = self.out / ".work"
        self.reports.mkdir(parents=True, exist_ok=True)
        self.work.mkdir(parents=True, exist_ok=True)
        self.files: dict[str, list[str]] = defaultdict(list)   # язык -> [relpath]
        self.exts: dict[str, list[str]] = defaultdict(list)    # '.py' -> [relpath]
        self._collect()

    def _collect(self):
        for dp, dns, fns in os.walk(self.root):
            here = Path(dp).resolve()
            dns[:] = [d for d in dns if d not in EXCLUDE_DIRS and not d.startswith(".")
                      and (here / d).resolve() != self.out]
            for fn in fns:
                ext = Path(fn).suffix.lower()
                if ext in EXT_LANG:
                    rp = os.path.relpath(here / fn, self.root)
                    self.files[EXT_LANG[ext]].append(rp)
                    self.exts[ext].append(rp)

    def norm(self, p: str) -> str:
        """Любой путь от сканера -> путь относительно корня проекта."""
        pp = Path(p)
        if not pp.is_absolute():
            pp = self.root / pp
        try:
            return os.path.relpath(pp.resolve(), self.root)
        except ValueError:
            return str(p)

    def of(self, *exts: str) -> list[str]:
        return sorted(f for e in exts for f in self.exts.get(e, []))


# --------------------------------------------------------------------------- #
#  Сканеры                                                                    #
# --------------------------------------------------------------------------- #

BANDIT_CWE_FALLBACK = {"B608": 89, "B602": 78, "B605": 78, "B607": 78, "B603": 78, "B105": 259, "B106": 259,
                       "B107": 259, "B201": 489, "B301": 502, "B302": 502, "B506": 502, "B324": 327,
                       "B303": 327, "B311": 330, "B101": 703, "B701": 79, "B703": 79}


def scan_bandit(ctx: Ctx):
    files = ctx.of(".py")
    if not files:
        return [], ToolStatus("bandit", "skipped", "нет .py файлов")
    p = run(["bandit", "-f", "json", "-q", *files], cwd=ctx.root)
    if p is None:
        return [], ToolStatus("bandit", "skipped", "не установлен (pip install bandit)")
    (ctx.reports / "bandit.json").write_text(p.stdout, encoding="utf-8")
    try:
        data = first_json(p.stdout)
    except json.JSONDecodeError:
        return [], ToolStatus("bandit", "error", p.stderr[:200])
    res = []
    for r in data.get("results", []):
        cwe = (r.get("issue_cwe") or {}).get("id") or BANDIT_CWE_FALLBACK.get(r["test_id"])
        res.append(Finding("bandit", r["test_id"], ctx.norm(r["filename"]), r["line_number"], cwe,
                           r["issue_text"], to_sev(r["issue_severity"]), "Python"))
    return res, ToolStatus("bandit", "ok", count=len(res))


def scan_cppcheck(ctx: Ctx):
    files = ctx.of(".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx")
    if not files:
        return [], ToolStatus("cppcheck", "skipped", "нет C/C++ файлов")
    p = run(["cppcheck", "--enable=warning,style,portability", "--inconclusive", "--xml", "--xml-version=2",
             "--suppress=missingIncludeSystem", "--suppress=missingInclude", "-q", *files], cwd=ctx.root)
    if p is None:
        return [], ToolStatus("cppcheck", "skipped", "не установлен (sudo apt install cppcheck)")
    (ctx.reports / "cppcheck.xml").write_text(p.stderr, encoding="utf-8")
    try:
        root = ET.fromstring(p.stderr)
    except ET.ParseError:
        return [], ToolStatus("cppcheck", "error", p.stderr[:200])
    res = []
    for e in root.iter("error"):
        loc = e.find("location")
        if loc is None or e.get("severity") == "information":
            continue
        cwe = int(e.get("cwe")) if e.get("cwe") else None
        res.append(Finding("cppcheck", e.get("id"), ctx.norm(loc.get("file")), int(loc.get("line")), cwe,
                           e.get("msg"), to_sev(e.get("severity")), "C++"))
    return res, ToolStatus("cppcheck", "ok", count=len(res))


def _pick_cwe(text: str) -> int | None:
    """Flawfinder пишет 'CWE-119!/CWE-120' или 'CWE-78, CWE-88' — выбираем наиболее подходящий."""
    nums = [int(n) for n in re.findall(r"CWE-(\d+)", text or "")]
    for n in nums:
        if n in CWE_INFO and n != 119:
            return n
    return nums[0] if nums else None


def scan_flawfinder(ctx: Ctx, minlevel: int):
    files = ctx.of(".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx")
    if not files:
        return [], ToolStatus("flawfinder", "skipped", "нет C/C++ файлов")
    p = run(["flawfinder", "--csv", f"--minlevel={minlevel}", *files], cwd=ctx.root)
    if p is None:
        return [], ToolStatus("flawfinder", "skipped", "не установлен (pip install flawfinder)")
    (ctx.reports / "flawfinder.csv").write_text(p.stdout, encoding="utf-8")
    res = []
    for row in csv.DictReader(p.stdout.splitlines()):
        lvl = int(row["Level"])
        sev = "high" if lvl >= 4 else "medium" if lvl == 3 else "low"
        res.append(Finding("flawfinder", f"{row['Category']}/{row['Name']}", ctx.norm(row["File"]),
                           int(row["Line"]), _pick_cwe(row["CWEs"] or row["Warning"]),
                           row["Warning"], sev, "C++"))
    return res, ToolStatus("flawfinder", "ok", count=len(res))


ESLINT_CWE = {
    "detect-child-process": 78, "detect-eval-with-expression": 95, "detect-non-literal-fs-filename": 22,
    "detect-non-literal-require": 829, "detect-unsafe-regex": 1333, "detect-non-literal-regexp": 1333,
    "detect-possible-timing-attacks": 208, "detect-pseudoRandomBytes": 338, "detect-buffer-noassert": 119,
    "detect-disable-mustache-escape": 79, "detect-no-csrf-before-method-override": 352,
}
ESLINT_CONFIG = """import security from "eslint-plugin-security";
export default [
  { ignores: ["**/node_modules/**"] },
  security.configs.recommended,
  { files: ["**/*.{js,mjs,cjs,jsx,ts}"], languageOptions: { ecmaVersion: "latest", sourceType: "commonjs" } },
];
"""


def scan_eslint(ctx: Ctx):
    files = ctx.of(".js", ".mjs", ".cjs", ".jsx", ".ts")
    if not files:
        return [], ToolStatus("eslint", "skipped", "нет JS-файлов")
    if not (shutil.which("node") and shutil.which("npm")):
        return [], ToolStatus("eslint", "skipped", "нужны node и npm (sudo apt install nodejs npm)")
    env = ctx.work / "eslint-env"
    binp = env / "node_modules" / ".bin" / "eslint"
    if not binp.exists():
        log("  · устанавливаю eslint + eslint-plugin-security (один раз)…")
        env.mkdir(parents=True, exist_ok=True)
        (env / "package.json").write_text('{"name":"eslint-env","private":true}', encoding="utf-8")
        p = run(["npm", "install", "--no-audit", "--no-fund", "eslint@9", "eslint-plugin-security@3"], cwd=env)
        if p is None or p.returncode != 0 or not binp.exists():
            return [], ToolStatus("eslint", "error", "npm install не удался: " + (p.stderr[-200:] if p else ""))
    cfg = env / "eslint.config.mjs"
    cfg.write_text(ESLINT_CONFIG, encoding="utf-8")
    p = run([str(binp), "-c", str(cfg), "--no-warn-ignored", "-f", "json", *files], cwd=ctx.root)
    if p is None:
        return [], ToolStatus("eslint", "error", "не удалось запустить")
    (ctx.reports / "eslint.json").write_text(p.stdout, encoding="utf-8")
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        return [], ToolStatus("eslint", "error", p.stderr[:200])
    res = []
    for f in data:
        for m in f.get("messages", []):
            rid = m.get("ruleId") or ""
            if not rid:       # ошибки парсинга
                continue
            short = rid.split("/")[-1]
            res.append(Finding("eslint", rid, ctx.norm(f["filePath"]), m.get("line", 0), ESLINT_CWE.get(short),
                               m["message"], "high" if m["severity"] == 2 else "medium", "JavaScript"))
    return res, ToolStatus("eslint", "ok", count=len(res))


# ---- Semgrep: кастомные правила под уязвимости практики (работают офлайн) ----

_JS_SRC = [{"pattern": p} for p in (
    "req.query", "req.query.$P", "req.query[...]", "req.body", "req.body.$P", "req.body[...]",
    "req.params", "req.params.$P", "req.params[...]", "req.headers.$P", "req.cookies.$P")]
_PY_SRC = [{"pattern": p} for p in (
    "request.form[...]", "request.form.get(...)", "request.args[...]", "request.args.get(...)",
    "request.values.get(...)", "request.get_json(...)", "request.json[...]", "request.cookies.get(...)")]


def _rule(rid, langs, sev, msg, cwe, owasp, **kw):
    r = {"id": rid, "languages": langs, "severity": sev, "message": msg,
         "metadata": {"cwe": [cwe], "owasp": [owasp]}}
    r.update(kw)
    return r


SEMGREP_RULES = {"rules": [
    _rule("vm-py-sqli-taint", ["python"], "ERROR",
          "Данные запроса попадают в SQL без параметризации (SQL Injection)",
          "CWE-89: SQL Injection", "A03:2021 - Injection", mode="taint",
          **{"pattern-sources": _PY_SRC,
             "pattern-sinks": [{"patterns": [{"pattern": "$DB.execute($Q, ...)"}, {"focus-metavariable": "$Q"}]},
                               {"patterns": [{"pattern": "$DB.executescript($Q)"}, {"focus-metavariable": "$Q"}]}]}),
    _rule("vm-py-idor-no-ownership-check", ["python"], "WARNING",
          "Объект выбирается по ID из URL без проверки владельца (IDOR)",
          "CWE-639: Authorization Bypass Through User-Controlled Key", "A01:2021 - Broken Access Control",
          patterns=[
              {"pattern-inside": "@$APP.route($PATH, ...)\ndef $F(...):\n    ...\n"},
              {"metavariable-regex": {"metavariable": "$PATH", "regex": "(?s).*<.*>.*"}},
              {"pattern": "$DB.execute($SQL, ($ID,))"},
              {"metavariable-regex": {
                  "metavariable": "$SQL",
                  "regex": r"(?is)^(?!.*(user_id|owner)).*from\s+(orders|invoices|payments|accounts|profiles|"
                           r"messages|documents|users)\s+where\s+id\s*=\s*\?.*"}}]),
    _rule("vm-py-login-no-rate-limit", ["python"], "WARNING",
          "Маршрут аутентификации без ограничения числа попыток (brute force)",
          "CWE-307: Improper Restriction of Excessive Authentication Attempts",
          "A07:2021 - Identification and Authentication Failures",
          patterns=[
              {"pattern": "@$APP.route($PATH, ...)\ndef $F(...):\n    ...\n"},
              {"metavariable-regex": {"metavariable": "$PATH", "regex": "(?i).*(login|signin|auth).*"}},
              {"pattern-not": "@$L.limit(...)\n@$APP.route($PATH, ...)\ndef $F(...):\n    ...\n"},
              {"pattern-not": "@$APP.route($PATH, ...)\n@$L.limit(...)\ndef $F(...):\n    ...\n"}]),
    _rule("vm-py-plaintext-password-in-sql", ["python"], "ERROR",
          "Пароль сравнивается в SQL в открытом виде (пароли хранятся без хеширования)",
          "CWE-256: Plaintext Storage of a Password", "A02:2021 - Cryptographic Failures",
          **{"pattern-regex": r"(?i)password\s*=\s*['\"]?\{"}),
    _rule("vm-tpl-jinja-safe-filter", ["generic"], "ERROR",
          "Фильтр |safe отключает экранирование вывода (XSS)",
          "CWE-79: Cross-site Scripting", "A03:2021 - Injection",
          paths={"include": ["*.html", "*.jinja", "*.jinja2", "*.j2"]},
          **{"pattern-regex": r"\{\{[^}]*\|\s*safe\s*\}\}"}),
    _rule("vm-js-sqli-taint", ["javascript", "typescript"], "ERROR",
          "Данные запроса попадают в SQL-строку (SQL Injection)",
          "CWE-89: SQL Injection", "A03:2021 - Injection", mode="taint",
          **{"pattern-sources": _JS_SRC,
             "pattern-sinks": [{"patterns": [{"pattern": "$DB.$M($Q, ...)"}, {"focus-metavariable": "$Q"},
                                             {"metavariable-regex": {"metavariable": "$M",
                                                                     "regex": "^(get|all|run|each|query|prepare)$"}}]}]}),
    _rule("vm-js-xss-taint", ["javascript", "typescript"], "ERROR",
          "Данные запроса выводятся в HTML-ответ без экранирования (XSS)",
          "CWE-79: Cross-site Scripting", "A03:2021 - Injection", mode="taint",
          **{"pattern-sources": _JS_SRC,
             "pattern-sinks": [{"patterns": [{"pattern": "$RES.send($X)"}, {"focus-metavariable": "$X"}]},
                               {"patterns": [{"pattern": "$RES.write($X)"}, {"focus-metavariable": "$X"}]}],
             "pattern-sanitizers": [{"pattern": "escape(...)"}, {"pattern": "escapeHtml(...)"},
                                    {"pattern": "$M.escape(...)"}, {"pattern": "sanitize(...)"},
                                    {"pattern": "DOMPurify.sanitize(...)"}]}),
    _rule("vm-js-cmdi-taint", ["javascript", "typescript"], "ERROR",
          "Данные запроса попадают в команду ОС (OS Command Injection)",
          "CWE-78: OS Command Injection", "A03:2021 - Injection", mode="taint",
          **{"pattern-sources": _JS_SRC,
             "pattern-sinks": [{"patterns": [{"pattern": "exec($C, ...)"}, {"focus-metavariable": "$C"}]},
                               {"patterns": [{"pattern": "execSync($C, ...)"}, {"focus-metavariable": "$C"}]},
                               {"patterns": [{"pattern": "$CP.exec($C, ...)"}, {"focus-metavariable": "$C"}]},
                               {"patterns": [{"pattern": "$CP.execSync($C, ...)"}, {"focus-metavariable": "$C"}]}]}),
]}


def scan_semgrep(ctx: Ctx, registry: list[str]):
    if not any(ctx.files.values()):
        return [], ToolStatus("semgrep", "skipped", "нет исходников")
    rules = ctx.work / "custom_rules.yml"
    rules.write_text(json.dumps(SEMGREP_RULES, ensure_ascii=False, indent=2), encoding="utf-8")  # JSON ⊂ YAML
    cmd = ["semgrep", "scan", "--config", str(rules)]
    for r in registry:
        cmd += ["--config", r]
    for d in sorted(EXCLUDE_DIRS):
        cmd += ["--exclude", d]
    cmd += ["--exclude", ctx.out.name, "--json", "--metrics=off", "--disable-version-check", "--quiet", "."]
    p = run(cmd, cwd=ctx.root)
    if p is None:
        return [], ToolStatus("semgrep", "skipped", "не установлен (pip install semgrep)")
    (ctx.reports / "semgrep.json").write_text(p.stdout, encoding="utf-8")
    try:
        data = first_json(p.stdout)
    except json.JSONDecodeError:
        return [], ToolStatus("semgrep", "error", p.stderr[-300:])
    res = []
    for r in data.get("results", []):
        md = r["extra"].get("metadata", {})
        cwes = md.get("cwe") or []
        cwes = [cwes] if isinstance(cwes, str) else cwes
        cwe = _pick_cwe(" ".join(cwes))
        path = r["path"]
        lang = EXT_LANG.get(Path(path).suffix.lower(), "Python")
        res.append(Finding("semgrep", r["check_id"].split(".")[-1], ctx.norm(path), r["start"]["line"], cwe,
                           r["extra"]["message"], to_sev(r["extra"]["severity"]), lang))
    return res, ToolStatus("semgrep", "ok", count=len(res))


def scan_zap(ctx: Ctx, url: str, full: bool, allow_remote: bool):
    host = urlparse(url).hostname or ""
    if host not in ("localhost", "127.0.0.1", "::1") and not allow_remote:
        return [], ToolStatus("zap", "skipped", f"{host} не локальный адрес; для чужих целей нужно разрешение "
                                                "владельца и флаг --allow-remote")
    if not shutil.which("docker"):
        return [], ToolStatus("zap", "skipped", "нужен docker (либо запустите ZAP вручную и положите zap.json "
                                                "в reports/)")
    ctx.reports.mkdir(exist_ok=True)
    os.chmod(ctx.reports, 0o777)     # контейнер пишет под другим uid
    script = "zap-full-scan.py" if full else "zap-baseline.py"
    log(f"  · ZAP ({script}) → {url}  (может занять несколько минут)")
    p = run(["docker", "run", "--rm", "--network", "host", "-v", f"{ctx.reports}:/zap/wrk:rw",
             "ghcr.io/zaproxy/zaproxy:stable", script, "-t", url, "-J", "zap.json", "-I"], timeout=3600)
    zf = ctx.reports / "zap.json"
    if p is None or not zf.exists():
        return [], ToolStatus("zap", "error", (p.stderr[-300:] if p else "docker не запустился"))
    res = []
    for site in json.loads(zf.read_text(encoding="utf-8")).get("site", []):
        for a in site.get("alerts", []):
            sev = {"3": "high", "2": "medium", "1": "low"}.get(str(a.get("riskcode")))
            cwe = int(a["cweid"]) if str(a.get("cweid", "")).lstrip("-").isdigit() and int(a["cweid"]) > 0 else None
            if not sev:      # informational
                continue
            for inst in (a.get("instances") or [{}])[:5]:
                res.append(Finding("zap", str(a.get("pluginid", a.get("alertRef", "zap"))),
                                   inst.get("uri", url), 0, cwe, a.get("name") or a.get("alert", ""), sev,
                                   "Web (DAST)"))
    return res, ToolStatus("zap", "ok", count=len(res))


# --------------------------------------------------------------------------- #
#  Объединение, обогащение, экспорт                                           #
# --------------------------------------------------------------------------- #

LINE_TOLERANCE = 3   # находки одного CWE в пределах N строк считаем одним дефектом


def merge(findings: list[Finding]) -> list[dict]:
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[(f.file, f.cwe)].append(f)
    clusters: list[list[Finding]] = []
    for items in groups.values():
        items.sort(key=lambda x: x.line)
        cur = [items[0]]
        for it in items[1:]:
            if it.line and it.line - cur[-1].line <= LINE_TOLERANCE:
                cur.append(it)
            else:
                clusters.append(cur)
                cur = [it]
        clusters.append(cur)
    return [_row(c) for c in clusters]


def _snippet(file: str, line: int, root: Path) -> str:
    try:
        return (root / file).read_text(encoding="utf-8", errors="replace").splitlines()[line - 1].strip()[:160]
    except Exception:
        return ""


def _row(c: list[Finding]) -> dict:
    c = sorted(c, key=lambda f: (-SEV_ORDER[f.severity], f.tool))
    best = c[0]
    cwe = best.cwe
    info = CWE_INFO.get(cwe) if cwe else None
    tool_sev = max((f.severity for f in c), key=lambda s: SEV_ORDER[s])
    cvss = info["cvss"] if info else {"high": 7.5, "medium": 5.3, "low": 3.1}[tool_sev]
    severity = ("Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium" if cvss >= 4 else "Low")
    lang = best.language
    cve = CVE_EXAMPLES.get((cwe, lang)) or CVE_EXAMPLES.get((cwe, "*")) or "—"
    return {
        "language": lang,
        "file": best.file,
        "line": min(f.line for f in c),
        "severity": severity,
        "cwe_id": f"CWE-{cwe}",
        "cwe_name": info["name"] if info else f"CWE-{cwe} (нет в локальной таблице)",
        "owasp": info["owasp"] if info else "—",
        "cve_example": cve,
        "cvss": cvss,
        "description": info["desc"] if info else best.message[:160],
        "tools": "+".join(sorted({f.tool for f in c})),
        "rule_ids": "; ".join(sorted({f"{f.tool}:{f.rule_id}" for f in c})),
        "tool_message": best.message.replace("\n", " ")[:300],
        "recommendation": info["rec"] if info else "См. описание CWE на cwe.mitre.org.",
        "code_snippet": "",
    }


COLUMNS = ["vuln_id", "language", "file", "line", "severity", "cwe_id", "cwe_name", "owasp", "cve_example",
           "cvss", "description", "tools", "rule_ids", "tool_message", "recommendation", "code_snippet"]
LANG_ORDER = {"Python": 0, "C++": 1, "JavaScript": 2, "Web (DAST)": 3}


def build_dataset(findings: list[Finding], ctx: Ctx, keep_noise: bool):
    kept, dropped = [], 0
    for f in findings:
        ok = f.cwe is not None and (f.cwe in CWE_INFO or f.severity in ("high", "medium"))
        if keep_noise or ok:
            if f.cwe is None:        # в датасете нужен CWE у каждой записи
                dropped += 1
                continue
            kept.append(f)
        else:
            dropped += 1
    rows = merge(kept)
    rows.sort(key=lambda r: (LANG_ORDER.get(r["language"], 9), r["file"], r["line"]))
    for i, r in enumerate(rows, 1):
        r["vuln_id"] = i
        r["code_snippet"] = _snippet(r["file"], r["line"], ctx.root) if r["language"] != "Web (DAST)" else ""
    return rows, dropped


def write_outputs(rows: list[dict], statuses: list[ToolStatus], dropped: int, ctx: Ctx):
    out = ctx.out
    with open(out / "vulnerabilities.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    (out / "vulnerabilities.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

    seen = sorted({int(r["cwe_id"][4:]) for r in rows})
    with open(out / "cwe_mapping.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["cwe_id", "cwe_name", "rank_2025", "owasp_category", "typical_impact"])
        for n in seen:
            i = CWE_INFO.get(n)
            o = i["owasp"] if i else "—"
            w.writerow([f"CWE-{n}", i["name"] if i else "—", RANK_2025.get(n, "—"),
                        f"{o} {OWASP_NAMES.get(o, '')}".strip(), i["impact"] if i else "—"])

    (out / "expert_assessment.md").write_text(expert_md(rows, statuses, dropped), encoding="utf-8")


def expert_md(rows, statuses, dropped) -> str:
    L = ["# Экспертная оценка безопасности", "",
         "_Сгенерировано автоматически `scan_vulns.py`. CVSS — экспертные оценки типового случая; "
         "перед сдачей проверьте CVE-примеры и ранги CWE Top 25 по первоисточникам (nvd.nist.gov, cwe.mitre.org)._",
         "", "## Сводка найденных уязвимостей", "",
         "| № | Язык | Файл:строка | CWE | OWASP | CVSS | Критичность | Найдено сканерами |",
         "|---|------|-------------|-----|-------|------|-------------|-------------------|"]
    for r in rows:
        L.append(f"| {r['vuln_id']} | {r['language']} | `{r['file']}:{r['line']}` | {r['cwe_id']} {r['cwe_name']} "
                 f"| {r['owasp']} | {r['cvss']} | {r['severity']} | {r['tools']} |")
    L += ["", "## Статистика", ""]
    by_cwe = Counter(r["cwe_id"] for r in rows)
    by_sev = Counter(r["severity"] for r in rows)
    L.append("- Всего уникальных уязвимостей: **%d** (классов CWE: %d)" % (len(rows), len(by_cwe)))
    L.append("- По критичности: " + ", ".join(f"{k}: {v}" for k, v in
                                              sorted(by_sev.items(), key=lambda kv: -SEV_ORDER[kv[0].lower()])))
    L.append("- По CWE: " + ", ".join(f"{k} ×{v}" for k, v in by_cwe.most_common()))
    L += ["", "## Ключевые выводы", ""]
    for n, (cwe, cnt) in enumerate(by_cwe.most_common(5), 1):
        i = CWE_INFO.get(int(cwe[4:]))
        rank = RANK_2025.get(int(cwe[4:]))
        L.append(f"{n}. **{cwe} — {i['name'] if i else '—'}** (экземпляров: {cnt})"
                 + (f"; место {rank} в CWE Top 25 2025" if rank else "")
                 + (f". Риск: {i['impact']}." if i else "."))
    L += ["", "## Рекомендации", ""]
    by_lang = defaultdict(dict)
    for r in rows:
        by_lang[r["language"]][r["cwe_id"]] = r["recommendation"]
    for lang, recs in by_lang.items():
        L.append(f"**{lang}**")
        L += [f"- `{c}`: {t}" for c, t in sorted(recs.items())]
        L.append("")
    L += ["## Использованные инструменты", "", "| Инструмент | Статус | Находок (сырых) | Комментарий |",
          "|---|---|---|---|"]
    L += [f"| {s.name} | {s.status} | {s.count} | {s.detail} |" for s in statuses]
    L += ["", f"Отфильтровано как шум (нет CWE / не относится к безопасности): {dropped}.", "",
          "## Ограничения", "",
          "- SAST не видит логику авторизации и бизнес-контекст: IDOR и слабая аутентификация ловятся только "
          "эвристическими правилами и требуют ручной проверки / DAST.",
          "- ZAP baseline — пассивное сканирование; SQLi/XSS/IDOR надёжно подтверждаются активным сканом "
          "(`--zap-full`) или ручными проверками.",
          "- Возможны ложные срабатывания — каждую запись стоит подтвердить вручную.", ""]
    return "\n".join(L)


# --------------------------------------------------------------------------- #
#  main                                                                       #
# --------------------------------------------------------------------------- #


def main() -> int:
    ap = argparse.ArgumentParser(description="SAST/DAST-анализ проекта и построение датасета CWE/CVE/OWASP")
    ap.add_argument("root", help="каталог проекта (например, ./vulnmart с vulnerable.cpp и vulnerable.js внутри)")
    ap.add_argument("--out", default="vuln_dataset", help="куда сохранить результаты (по умолчанию ./vuln_dataset)")
    ap.add_argument("--skip", default="", help="через запятую: bandit,cppcheck,flawfinder,eslint,semgrep,zap")
    ap.add_argument("--flawfinder-minlevel", type=int, default=3, help="порог Flawfinder 0-5 (по умолчанию 3)")
    ap.add_argument("--semgrep-registry", nargs="*", default=[],
                    help="доп. наборы правил из реестра (нужен интернет), напр.: p/python p/javascript p/flask")
    ap.add_argument("--zap-url", help="URL запущенного локального приложения для DAST (Docker + OWASP ZAP)")
    ap.add_argument("--zap-full", action="store_true", help="активный скан ZAP вместо пассивного baseline")
    ap.add_argument("--allow-remote", action="store_true",
                    help="разрешить DAST по нелокальному адресу (только при наличии разрешения владельца!)")
    ap.add_argument("--keep-noise", action="store_true", help="не отфильтровывать малозначимые находки")
    a = ap.parse_args()

    root = Path(a.root)
    if not root.is_dir():
        log(f"Каталог не найден: {root}")
        return 2
    skip = {s.strip().lower() for s in a.skip.split(",") if s.strip()}
    ctx = Ctx(root, Path(a.out))
    log(f"Проект: {ctx.root}")
    log("Найдено файлов: " + (", ".join(f"{k}: {len(v)}" for k, v in ctx.files.items()) or "нет"))

    jobs = [
        ("bandit", lambda: scan_bandit(ctx)),
        ("cppcheck", lambda: scan_cppcheck(ctx)),
        ("flawfinder", lambda: scan_flawfinder(ctx, a.flawfinder_minlevel)),
        ("eslint", lambda: scan_eslint(ctx)),
        ("semgrep", lambda: scan_semgrep(ctx, a.semgrep_registry)),
    ]
    if a.zap_url:
        jobs.append(("zap", lambda: scan_zap(ctx, a.zap_url, a.zap_full, a.allow_remote)))

    findings: list[Finding] = []
    statuses: list[ToolStatus] = []
    for name, fn in jobs:
        if name in skip:
            statuses.append(ToolStatus(name, "skipped", "отключён через --skip"))
            continue
        log(f"▶ {name}…")
        try:
            res, st = fn()
        except Exception as e:      # один упавший сканер не должен ломать весь прогон
            res, st = [], ToolStatus(name, "error", f"{type(e).__name__}: {e}")
        findings += res
        statuses.append(st)
        log(f"  {st.status}: {st.count} находок {st.detail}")

    rows, dropped = build_dataset(findings, ctx, a.keep_noise)
    write_outputs(rows, statuses, dropped, ctx)

    log("\n=== ИТОГ ===")
    for r in rows:
        log(f"#{r['vuln_id']:<2} [{r['severity']:<8}] {r['cwe_id']:<8} {r['file']}:{r['line']:<4} "
            f"({r['tools']})  {r['cwe_name']}")
    log(f"\nУникальных уязвимостей: {len(rows)} (шум отфильтрован: {dropped})")
    log(f"Результаты: {ctx.out}/  → vulnerabilities.csv, vulnerabilities.json, cwe_mapping.csv, "
        "expert_assessment.md, reports/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
