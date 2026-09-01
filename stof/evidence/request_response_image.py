"""Layer 12 — styled request/response evidence images.

Burp's own REST API only ever hands back plain request/response text
(`Finding.request_raw` / `response_raw`) -- there's no rendered
screenshot of its Repeater/Proxy panes to capture, since driving Burp's
desktop UI for a screenshot would mean every scan needs Burp's window
visibly open, which is exactly the "Burp Pro Capability = Partial/No"
constraint this project already operates under (see the sprint plan's
own header). Instead, this renders that same text into a Burp-style
dark code panel PNG at report-build time -- a real image embedded in
the HTML report, not a plain-text `<pre>` block, produced from data
this project already has.

Reused by both live-browser findings (`EvidenceCollector.capture()`,
which additionally screenshots the actual page) and non-browser ones
(Burp Active Scan issues, `capture_raw()`), so every `Finding` gets a
consistent, legible request/response image regardless of which probe
technique produced it.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from stof.core.logger import get_logger

_log = get_logger("evidence.request_response_image")

_ASSETS_DIR = Path(__file__).parent / "assets" / "fonts"
_FONT_CANDIDATES = (
    _ASSETS_DIR / "DejaVuSansMono.ttf",
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
)
_BOLD_FONT_CANDIDATES = (
    _ASSETS_DIR / "DejaVuSansMono-Bold.ttf",
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"),
)

_WIDTH = 900
_FONT_SIZE = 13
_LINE_HEIGHT = 19
_PADDING = 16
_SECTION_GAP = 10
_MAX_LINES_PER_SECTION = 40
_MAX_CHARS_PER_LINE = 108

# A dark "Repeater"-style palette -- deliberately independent of the
# HTML report's own light/dark theme tokens, since this is a baked PNG
# rendered once at capture time, not a page that re-themes at view time.
_BG = (13, 17, 23)
_PANEL = (18, 24, 38)
_BORDER = (42, 52, 80)
_TEXT = (226, 232, 240)
_MUTED = (142, 152, 184)
_ACCENT_REQUEST = (96, 205, 255)
_ACCENT_RESPONSE = (77, 219, 140)
_HEADER_KEY = (167, 191, 255)


def _load_font(candidates: tuple[Path, ...], size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in candidates:
        if path.is_file():
            try:
                return ImageFont.truetype(str(path), size)
            except OSError as exc:
                _log.warning(f"could not load font '{path}': {exc}")
    _log.warning("no monospace TrueType font found -- falling back to Pillow's bitmap default (fixed small size)")
    return ImageFont.load_default()


def _wrap_line(line: str, max_chars: int) -> list[str]:
    if len(line) <= max_chars:
        return [line]
    return [line[i : i + max_chars] for i in range(0, len(line), max_chars)] or [""]


def _prepare_lines(raw: str) -> tuple[list[str], bool]:
    """Splits + wraps `raw` into display lines, capped at
    `_MAX_LINES_PER_SECTION` so one huge response body can't blow the
    image up to an unusable size. Returns (lines, was_truncated)."""
    lines: list[str] = []
    for line in raw.replace("\r\n", "\n").split("\n"):
        lines.extend(_wrap_line(line, _MAX_CHARS_PER_LINE))
        if len(lines) >= _MAX_LINES_PER_SECTION:
            return lines[:_MAX_LINES_PER_SECTION], True
    return lines, False


def _line_color(line: str, index: int, is_first_section_line: bool) -> tuple[int, int, int]:
    if is_first_section_line:
        return _TEXT
    if ":" in line and not line.startswith((" ", "\t", "{", "[", '"')):
        return _HEADER_KEY
    return _MUTED if index == 0 else _TEXT


def render_http_pair_image(request_raw: str, response_raw: str, output_path: str | Path, title: str | None = None) -> Path:
    """Renders `request_raw` / `response_raw` as a single dark,
    two-section PNG (REQUEST above RESPONSE) and writes it to
    `output_path`. Never raises -- evidence capture is opportunistic
    (Layer 12's own rule), so a rendering failure is logged and the
    caller simply gets a missing file, not a crashed scan."""
    output_path = Path(output_path)
    font = _load_font(_FONT_CANDIDATES, _FONT_SIZE)
    bold_font = _load_font(_BOLD_FONT_CANDIDATES, _FONT_SIZE)

    request_lines, request_truncated = _prepare_lines(request_raw)
    response_lines, response_truncated = _prepare_lines(response_raw)
    if request_truncated:
        request_lines.append("... (truncated)")
    if response_truncated:
        response_lines.append("... (truncated)")

    title_height = _LINE_HEIGHT + 6 if title else 0
    section_label_height = _LINE_HEIGHT + 4
    height = (
        _PADDING * 2
        + title_height
        + section_label_height + len(request_lines) * _LINE_HEIGHT
        + _SECTION_GAP
        + section_label_height + len(response_lines) * _LINE_HEIGHT
    )

    image = Image.new("RGB", (_WIDTH, height), _BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle([(0, 0), (_WIDTH - 1, height - 1)], outline=_BORDER, width=1)

    y = _PADDING
    if title:
        draw.text((_PADDING, y), title, font=bold_font, fill=_TEXT)
        y += title_height

    def draw_section(label: str, accent: tuple[int, int, int], lines: list[str], y: int) -> int:
        draw.text((_PADDING, y), label, font=bold_font, fill=accent)
        y += section_label_height
        panel_top = y
        panel_bottom = y + len(lines) * _LINE_HEIGHT
        draw.rectangle([(_PADDING - 6, panel_top - 4), (_WIDTH - _PADDING + 6, panel_bottom)], fill=_PANEL)
        for i, line in enumerate(lines):
            color = _line_color(line, i, is_first_section_line=(i == 0))
            draw.text((_PADDING, y), line, font=font, fill=color)
            y += _LINE_HEIGHT
        return y

    y = draw_section("REQUEST", _ACCENT_REQUEST, request_lines, y)
    y += _SECTION_GAP
    draw_section("RESPONSE", _ACCENT_RESPONSE, response_lines, y)

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        image.save(output_path, format="PNG")
    except OSError as exc:
        _log.warning(f"could not write request/response evidence image '{output_path}': {exc}")
    return output_path
