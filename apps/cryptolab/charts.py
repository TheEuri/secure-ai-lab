"""Server-side SVG charts.

The application's CSP forbids inline scripts and inline ``style``
attributes, so charts are rendered as SVG on the server.  Colours come from
CSS classes (``series-0`` …) defined in ``cryptolab.css``; the heatmap uses
the ``fill`` presentation attribute, which CSP does not treat as a style.
"""

from markupsafe import Markup, escape


def compact_number(value):
    value = float(value)
    for limit, suffix in ((1e9, "G"), (1e6, "M"), (1e3, "k")):
        if abs(value) >= limit:
            scaled = value / limit
            return f"{scaled:.1f}{suffix}" if scaled < 10 else f"{scaled:.0f}{suffix}"
    return f"{value:.3g}"


_fmt = compact_number


def hbar_chart(values, labels, *, width=760, row=22, label_w=190, title=""):
    """Horizontal bars: readable when there are many long category labels."""

    peak = max(values, default=1) or 1
    height = row * len(values) + 8
    plot_w = width - label_w - 70
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="{escape(title)}">']
    for i, (value, label) in enumerate(zip(values, labels)):
        y = 4 + i * row
        w = max(1.0, plot_w * value / peak)
        parts.append(f'<text class="axis" x="{label_w - 6}" y="{y + row * 0.65:.1f}" '
                     f'text-anchor="end">{escape(label)}</text>'
                     f'<rect class="series-0" x="{label_w}" y="{y + 3}" width="{w:.1f}" '
                     f'height="{row - 6}"><title>{escape(label)}: {value}</title></rect>'
                     f'<text class="axis" x="{label_w + w + 4:.1f}" y="{y + row * 0.65:.1f}">'
                     f'{compact_number(value)}</text>')
    parts.append("</svg>")
    return Markup("".join(parts))


def bar_chart(series, labels, *, series_names=(), width=640, height=240, y_max=None,
              percent=False, title=""):
    """Grouped vertical bars; ``series`` is a list of equally long value lists."""

    pad_l, pad_b, pad_t = 52, 46, 18
    plot_w, plot_h = width - pad_l - 10, height - pad_b - pad_t
    peak = y_max or max((v for s in series for v in s), default=1) or 1
    n, k = len(labels), max(1, len(series))
    group_w = plot_w / max(1, n)
    bar_w = group_w * 0.8 / k
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="{escape(title)}">']
    for frac in (0, 0.25, 0.5, 0.75, 1):
        y = pad_t + plot_h * (1 - frac)
        label = f"{frac * peak:.0%}" if percent else _fmt(frac * peak)
        parts.append(f'<line class="grid" x1="{pad_l}" x2="{width - 10}" y1="{y:.1f}" y2="{y:.1f}"/>'
                     f'<text class="axis" x="{pad_l - 4}" y="{y + 4:.1f}" text-anchor="end">{label}</text>')
    for si, values in enumerate(series):
        for i, value in enumerate(values):
            h = plot_h * min(value, peak) / peak
            x = pad_l + i * group_w + group_w * 0.1 + si * bar_w
            shown = f"{value:.1%}" if percent else _fmt(value)
            parts.append(f'<rect class="series-{si}" x="{x:.1f}" y="{pad_t + plot_h - h:.1f}" '
                         f'width="{bar_w:.1f}" height="{h:.1f}"><title>{escape(labels[i])}: '
                         f'{shown}</title></rect>')
    for i, label in enumerate(labels):
        x = pad_l + i * group_w + group_w / 2
        parts.append(f'<text class="axis" x="{x:.1f}" y="{height - pad_b + 16}" '
                     f'text-anchor="middle">{escape(label)}</text>')
    for si, name in enumerate(series_names):
        x = pad_l + si * 150
        parts.append(f'<rect class="series-{si}" x="{x}" y="{height - 16}" width="10" height="10"/>'
                     f'<text class="axis" x="{x + 14}" y="{height - 7}">{escape(name)}</text>')
    parts.append("</svg>")
    return Markup("".join(parts))


def histogram(values, *, width=640, height=160, css="series-0", title=""):
    """Dense bar histogram without per-bar labels (e.g. 256 byte values)."""

    peak = max(values, default=1) or 1
    bar_w = (width - 20) / max(1, len(values))
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="{escape(title)}">']
    for i, value in enumerate(values):
        h = (height - 24) * value / peak
        parts.append(f'<rect class="{css}" x="{10 + i * bar_w:.2f}" y="{height - 14 - h:.1f}" '
                     f'width="{max(bar_w - 0.3, 0.5):.2f}" height="{h:.1f}"/>')
    parts.append(f'<text class="axis" x="10" y="{height - 2}">0</text>'
                 f'<text class="axis" x="{width - 10}" y="{height - 2}" text-anchor="end">'
                 f'{len(values) - 1}</text></svg>')
    return Markup("".join(parts))


def line_chart(series, *, series_names=(), x_labels=(), width=760, height=240, title=""):
    pad_l, pad_b, pad_t = 52, 30, 14
    plot_w, plot_h = width - pad_l - 10, height - pad_b - pad_t
    peak = max((v for s in series for v in s), default=1) or 1
    n = max((len(s) for s in series), default=1)
    step = plot_w / max(1, n - 1)
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="{escape(title)}">']
    for frac in (0, 0.5, 1):
        y = pad_t + plot_h * (1 - frac)
        parts.append(f'<line class="grid" x1="{pad_l}" x2="{width - 10}" y1="{y:.1f}" y2="{y:.1f}"/>'
                     f'<text class="axis" x="{pad_l - 4}" y="{y + 4:.1f}" text-anchor="end">'
                     f'{compact_number(int(frac * peak))}</text>')
    for si, values in enumerate(series):
        points = " ".join(f"{pad_l + i * step:.1f},{pad_t + plot_h * (1 - v / peak):.1f}"
                          for i, v in enumerate(values))
        parts.append(f'<polyline class="line series-{si}" points="{points}"/>')
    if x_labels:
        for i in range(0, len(x_labels), max(1, len(x_labels) // 7)):
            parts.append(f'<text class="axis" x="{pad_l + i * step:.1f}" y="{height - 10}" '
                         f'text-anchor="middle">{escape(x_labels[i])}</text>')
    for si, name in enumerate(series_names):
        if not name:
            continue
        x = pad_l + si * 170
        parts.append(f'<rect class="series-{si}" x="{x}" y="0" width="10" height="10"/>'
                     f'<text class="axis" x="{x + 14}" y="9">{escape(name)}</text>')
    parts.append("</svg>")
    return Markup("".join(parts))


def heatmap(matrix, *, cells=32, size=256, title=""):
    """Downsampled SAC heatmap: white = 0.5 (ideal), red/blue = deviation."""

    n = len(matrix)
    block = max(1, n // cells)
    cell = size / cells
    parts = [f'<svg class="chart heatmap" viewBox="0 0 {size} {size}" role="img" '
             f'aria-label="{escape(title)}">']
    for r in range(cells):
        for c in range(cells):
            vals = [matrix[i][j] for i in range(r * block, (r + 1) * block)
                    for j in range(c * block, (c + 1) * block)]
            v = sum(vals) / len(vals)
            d = min(1.0, abs(v - 0.5) * 2)
            shade = int(255 * (1 - d))
            color = f"rgb(255,{shade},{shade})" if v < 0.5 else f"rgb({shade},{shade},255)"
            parts.append(f'<rect x="{c * cell:.1f}" y="{r * cell:.1f}" width="{cell:.1f}" '
                         f'height="{cell:.1f}" fill="{color}"/>')
    parts.append("</svg>")
    return Markup("".join(parts))
