#!/usr/bin/env python3
"""HTML 페이지를 5가지 관점(title, 내부 링크, img alt, viewport, UTF-8 인코딩)으로 점검한다.

표준 라이브러리(html.parser)만 사용하며 외부 의존성이 없다.

사용법:
    python check_page.py [파일...]

인자가 없으면 현재 디렉터리 하위의 모든 *.html 파일을 재귀적으로 점검한다
(.git, node_modules 디렉터리는 제외).
"""
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

EXTERNAL_SCHEMES = ("http://", "https://", "mailto:", "tel:", "javascript:", "data:")
EXCLUDED_DIR_NAMES = {".git", "node_modules"}


class PageChecker(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = None
        self._title_open = False
        self.has_viewport = False
        self.viewport_content = ""
        self.charset = None
        self.images = []
        self.ids = set()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)

        el_id = attr_dict.get("id")
        if el_id:
            self.ids.add(el_id)
        if tag == "a" and attr_dict.get("name"):
            self.ids.add(attr_dict["name"])

        if tag == "title":
            self._title_open = True
            self.title = ""
        elif tag == "meta":
            name = (attr_dict.get("name") or "").lower()
            if name == "viewport":
                self.has_viewport = True
                self.viewport_content = attr_dict.get("content", "") or ""
            if "charset" in attr_dict:
                self.charset = attr_dict["charset"]
            http_equiv = (attr_dict.get("http-equiv") or "").lower()
            if http_equiv == "content-type":
                content = attr_dict.get("content", "") or ""
                for part in content.split(";"):
                    part = part.strip()
                    if part.lower().startswith("charset="):
                        self.charset = part.split("=", 1)[1].strip()
        elif tag == "img":
            self.images.append({
                "has_alt": "alt" in attr_dict,
                "line": self.getpos()[0],
                "src": attr_dict.get("src", ""),
            })
        elif tag == "a":
            href = attr_dict.get("href")
            if href is not None:
                self.links.append({"href": href, "line": self.getpos()[0]})

    def handle_endtag(self, tag):
        if tag == "title":
            self._title_open = False

    def handle_data(self, data):
        if self._title_open and self.title is not None:
            self.title += data


def classify(file_path: Path, checker: PageChecker, raw_bytes: bytes):
    critical, warning, suggestion = [], [], []

    # 1. <title>
    if checker.title is None:
        warning.append("<title> 태그가 없습니다 — 브라우저 탭/북마크/SEO에 영향을 줍니다.")
    elif not checker.title.strip():
        suggestion.append("<title> 태그는 있지만 내용이 비어 있습니다.")

    # 2. 내부 링크
    for link in checker.links:
        href = link["href"].strip()
        if not href:
            continue
        if href.lower().startswith(EXTERNAL_SCHEMES) or href.startswith("//"):
            continue
        if href.startswith("#"):
            fragment = href[1:]
            if fragment and fragment not in checker.ids:
                critical.append(
                    f'내부 링크 깨짐: href="{href}" — id="{fragment}" 요소를 찾을 수 없습니다 '
                    f'({link["line"]}번째 줄).'
                )
            continue
        parsed = urlsplit(href)
        if parsed.scheme:
            continue
        if href.startswith("/"):
            suggestion.append(
                f'루트 상대경로 링크는 자동 검증할 수 없습니다: href="{href}" '
                f'({link["line"]}번째 줄) — 수동 확인이 필요합니다.'
            )
            continue
        if parsed.path:
            target = (file_path.parent / parsed.path).resolve()
            if not target.exists():
                critical.append(
                    f'내부 링크 깨짐: href="{href}" — 파일을 찾을 수 없습니다 '
                    f'({link["line"]}번째 줄).'
                )

    # 3. img alt
    missing_alt = [img for img in checker.images if not img["has_alt"]]
    if missing_alt:
        lines = ", ".join(str(img["line"]) for img in missing_alt)
        warning.append(
            f"<img> {len(missing_alt)}개에 alt 속성이 없습니다 ({lines}번째 줄)."
        )

    # 4. 모바일 viewport
    if not checker.has_viewport:
        critical.append(
            "모바일 viewport 메타 태그가 없습니다 — 모바일 화면에서 레이아웃이 깨질 수 있습니다."
        )
    elif "width=device-width" not in checker.viewport_content.replace(" ", "").lower():
        suggestion.append(
            f'viewport 메타 태그는 있지만 권장 값(width=device-width)이 없습니다: '
            f'content="{checker.viewport_content}"'
        )

    # 5. UTF-8 인코딩
    has_non_ascii = any(b > 127 for b in raw_bytes)
    if checker.charset is None:
        if has_non_ascii:
            critical.append(
                "한글 등 비ASCII 문자가 있는데 charset(UTF-8) 선언이 없습니다 — 글자가 깨져 보일 수 있습니다."
            )
        else:
            suggestion.append(
                'charset 선언이 없습니다. 향후 한글 등 콘텐츠 추가에 대비해 '
                '<meta charset="UTF-8">을 추가하는 것을 권장합니다.'
            )
    elif checker.charset.lower().replace("-", "") != "utf8":
        critical.append(
            f'charset이 UTF-8이 아닙니다: charset="{checker.charset}" — 한글이 깨질 수 있습니다.'
        )

    return critical, warning, suggestion


def collect_files(args):
    if args:
        return [Path(a) for a in args]
    return sorted(
        p for p in Path(".").rglob("*.html")
        if not EXCLUDED_DIR_NAMES.intersection(p.parts)
    )


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    files = collect_files(sys.argv[1:])
    if not files:
        print("점검할 HTML 파일을 찾지 못했습니다.")
        return 1

    total = {"critical": 0, "warning": 0, "suggestion": 0}

    for f in files:
        if not f.exists():
            print(f"\n=== {f} ===\n파일을 찾을 수 없습니다.")
            continue

        raw = f.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        checker = PageChecker()
        checker.feed(text)
        critical, warning, suggestion = classify(f, checker, raw)

        total["critical"] += len(critical)
        total["warning"] += len(warning)
        total["suggestion"] += len(suggestion)

        print(f"\n=== {f} ===")
        if not (critical or warning or suggestion):
            print("🟢 문제 없음 — 5가지 항목 모두 통과했습니다.")
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
