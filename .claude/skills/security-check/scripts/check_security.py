#!/usr/bin/env python3
"""HTML/JS 파일을 4가지 관점(하드코딩 시크릿, innerHTML XSS, console.log 노출, http:// 외부 요청)으로 점검한다.

표준 라이브러리(re)만 사용하며 외부 의존성이 없다.

사용법:
    python check_security.py [파일...]

인자가 없으면 현재 디렉터리 하위의 모든 *.html, *.js 파일을 재귀적으로 점검한다
(.git, node_modules 디렉터리는 제외).
"""
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

EXCLUDED_DIR_NAMES = {".git", "node_modules"}
TARGET_GLOBS = ("*.html", "*.js")

# 1. 하드코딩된 비밀번호·API 키
SECRET_KEY_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|access[_-]?token|private[_-]?key|client[_-]?secret|"
    r"auth[_-]?key)\b\s*[:=]\s*(['\"])(?P<value>(?:(?!\2).)+)\2"
)
PLACEHOLDER_PATTERN = re.compile(
    r"(?i)(your[_-]?|xxx|changeme|change_me|example|insert|dummy|placeholder|"
    r"sample|test[_-]?key|<|\{\{|\$\{|process\.env|import\.meta\.env)"
)
AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PRIVATE_KEY_BLOCK_PATTERN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

# 2. innerHTML XSS
INNERHTML_ASSIGN_PATTERN = re.compile(r"\.innerHTML\s*(\+?=)\s*(?P<rhs>.+?);?\s*$")
STRING_LITERAL_ONLY_PATTERN = re.compile(r"^(['\"])(?:(?!\1).)*\1$")
ESCAPE_HINT_PATTERN = re.compile(
    r"(?i)(escapeHtml|escape_html|sanitize|dompurify|encodeURIComponent|encodeHTML)"
)

# 3. console.log 민감정보 노출
CONSOLE_CALL_PATTERN = re.compile(r"console\.(log|debug|info|warn|error)\s*\((?P<args>.*)\)")
SENSITIVE_KEYWORD_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|credential|session[_-]?id|auth)\b"
)

# 4. http:// 외부 요청
HTTP_URL_PATTERN = re.compile(r"(['\"])http://(?P<rest>[^'\"]+)\1")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}


def mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def classify(file_path: Path, text: str):
    critical, warning, suggestion = [], [], []
    lines = text.splitlines()

    for lineno, line in enumerate(lines, start=1):
        # 1. 하드코딩된 비밀번호·API 키
        m = SECRET_KEY_PATTERN.search(line)
        if m:
            value = m.group("value")
            if value and not PLACEHOLDER_PATTERN.search(value):
                critical.append(
                    f'{file_path}:{lineno} — 하드코딩된 시크릿으로 보입니다: '
                    f'`{m.group(0).split("=")[0].strip()}...` 값="{mask(value)}"'
                )

        # 2. innerHTML XSS
        m = INNERHTML_ASSIGN_PATTERN.search(line)
        if m:
            rhs = m.group("rhs").strip()
            if not STRING_LITERAL_ONLY_PATTERN.match(rhs):
                if ESCAPE_HINT_PATTERN.search(rhs):
                    suggestion.append(
                        f'{file_path}:{lineno} — innerHTML에 이스케이프/새니타이즈 함수를 거친 값이 '
                        f'들어가는 것으로 보이나, 실제 구현이 안전한지 확인이 필요합니다: `{line.strip()}`'
                    )
                else:
                    critical.append(
                        f'{file_path}:{lineno} — 이스케이프 없이 innerHTML에 변수/템플릿을 대입합니다 '
                        f'(XSS 가능성): `{line.strip()}`'
                    )

        # 3. console.log 민감정보 노출
        m = CONSOLE_CALL_PATTERN.search(line)
        if m and SENSITIVE_KEYWORD_PATTERN.search(m.group("args")):
            critical.append(
                f'{file_path}:{lineno} — console.{m.group(1)}가 민감정보로 보이는 값을 '
                f'출력합니다: `{line.strip()}`'
            )

        # 4. http:// 외부 요청
        for m in HTTP_URL_PATTERN.finditer(line):
            host = urlsplit("http://" + m.group("rest")).hostname or ""
            item = f'{file_path}:{lineno} — http:// 평문 요청/리소스: `http://{m.group("rest")}`'
            if host in LOCAL_HOSTS:
                warning.append(item + " (로컬 호스트 — 배포 전 https:// 전환 확인 필요)")
            else:
                critical.append(item + " (외부 도메인 — 평문 통신으로 데이터 노출/변조 위험)")

    # 하드코딩 시크릿: AWS 키, 개인키 블록은 파일 전체에서 위치를 찾아 줄 번호로 환산
    for m in AWS_KEY_PATTERN.finditer(text):
        lineno = text.count("\n", 0, m.start()) + 1
        critical.append(f'{file_path}:{lineno} — AWS Access Key ID로 보이는 값이 하드코딩되어 있습니다.')

    for m in PRIVATE_KEY_BLOCK_PATTERN.finditer(text):
        lineno = text.count("\n", 0, m.start()) + 1
        critical.append(f'{file_path}:{lineno} — 개인키(private key) 블록이 파일에 포함되어 있습니다.')

    return critical, warning, suggestion


def collect_files(args):
    if args:
        return [Path(a) for a in args]
    files = []
    for pattern in TARGET_GLOBS:
        files.extend(
            p for p in Path(".").rglob(pattern)
            if not EXCLUDED_DIR_NAMES.intersection(p.parts)
        )
    return sorted(set(files))


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    files = collect_files(sys.argv[1:])
    if not files:
        print("점검할 HTML/JS 파일을 찾지 못했습니다.")
        return 1

    total = {"critical": 0, "warning": 0, "suggestion": 0}

    for f in files:
        if not f.exists():
            print(f"\n=== {f} ===\n파일을 찾을 수 없습니다.")
            continue

        raw = f.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        critical, warning, suggestion = classify(f, text)

        total["critical"] += len(critical)
        total["warning"] += len(warning)
        total["suggestion"] += len(suggestion)

        print(f"\n=== {f} ===")
        if not (critical or warning or suggestion):
            print("🟢 문제 없음 — 4가지 항목 모두 통과했습니다.")
            continue
        if critical:
            print("🔴 심각")
            for item in critical:
                print(f"  - {item}")
        if warning:
            print("🟡 주의")
            for item in warning:
                print(f"  - {item}")
        if suggestion:
            print("🟢 제안")
            for item in suggestion:
                print(f"  - {item}")

    print(
        f"\n요약: 🔴 {total['critical']}건 · 🟡 {total['warning']}건 · 🟢 {total['suggestion']}건"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
