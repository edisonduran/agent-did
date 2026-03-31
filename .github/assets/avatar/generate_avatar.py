from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter


SIZE = 1024
ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "agent-did-avatar.png"


def ellipse_bbox(cx: float, cy: float, rx: float, ry: float):
    return (cx - rx, cy - ry, cx + rx, cy + ry)


def hex_points(cx: float, cy: float, r: float):
    h = r * 0.8660254038
    return [
        (cx - r, cy),
        (cx - r / 2, cy - h),
        (cx + r / 2, cy - h),
        (cx + r, cy),
        (cx + r / 2, cy + h),
        (cx - r / 2, cy + h),
        (cx - r, cy),
    ]


def draw_background(base: Image.Image):
    overlay = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    draw.ellipse((-120, 570, 500, 1180), fill=(255, 138, 61, 72))
    draw.ellipse((560, -120, 1150, 470), fill=(0, 171, 181, 70))
    draw.ellipse((170, 120, 920, 980), fill=(148, 175, 196, 28))

    grid = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    grid_draw = ImageDraw.Draw(grid)
    for row in range(-1, 7):
        for col in range(-1, 7):
            x = 130 + col * 175 + (87 if row % 2 else 0)
            y = 110 + row * 152
            points = hex_points(x, y, 60)
            grid_draw.line(points, fill=(220, 230, 238, 24), width=3)

    overlay = overlay.filter(ImageFilter.GaussianBlur(60))
    base.alpha_composite(overlay)
    base.alpha_composite(grid)


def draw_badge(base: Image.Image):
    shadow = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    shadow_draw = ImageDraw.Draw(shadow)
    badge_box = ellipse_bbox(512, 512, 310, 310)
    shadow_draw.ellipse((badge_box[0] + 8, badge_box[1] + 30, badge_box[2] + 8, badge_box[3] + 30), fill=(2, 8, 18, 120))
    shadow = shadow.filter(ImageFilter.GaussianBlur(24))
    base.alpha_composite(shadow)

    badge = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(badge)

    draw.ellipse(badge_box, fill=(14, 27, 42, 224), outline=(176, 236, 240, 210), width=8)
    draw.ellipse(ellipse_bbox(512, 512, 278, 278), fill=(20, 38, 60, 172))
    draw.ellipse((252, 230, 508, 466), fill=(255, 255, 255, 34))

    for expand, alpha in [(20, 60), (42, 36), (64, 18)]:
        draw.ellipse(ellipse_bbox(512, 512, 310 + expand, 310 + expand), outline=(0, 171, 181, alpha), width=6)

    for cx, cy, fill in [
        (268, 358, (255, 138, 61, 220)),
        (770, 332, (228, 195, 103, 220)),
        (560, 800, (0, 171, 181, 230)),
    ]:
        draw.ellipse(ellipse_bbox(cx, cy, 20, 20), fill=fill, outline=(244, 240, 232, 220), width=4)

    badge = badge.filter(ImageFilter.GaussianBlur(0.3))
    base.alpha_composite(badge)


def draw_agent_symbol(base: Image.Image):
    color = (191, 241, 244, 255)
    accent = (228, 195, 103, 255)
    width = 16
    draw = ImageDraw.Draw(base)
    scale = 1.58
    cx = 512
    cy = 512

    draw.line(
        [
            (cx - 112 * scale, cy - 70 * scale),
            (cx - 48 * scale, cy - 70 * scale),
            (cx - 10 * scale, cy - 42 * scale),
            (cx + 22 * scale, cy - 42 * scale),
        ],
        fill=color,
        width=width,
        joint="curve",
    )
    draw.line(
        [
            (cx - 136 * scale, cy - 16 * scale),
            (cx - 66 * scale, cy - 16 * scale),
            (cx - 6 * scale, cy + 14 * scale),
        ],
        fill=color,
        width=width,
        joint="curve",
    )
    draw.line(
        [
            (cx - 116 * scale, cy + 50 * scale),
            (cx - 56 * scale, cy + 50 * scale),
            (cx - 4 * scale, cy + 80 * scale),
        ],
        fill=color,
        width=width,
        joint="curve",
    )

    profile = [
        (cx - 70 * scale, cy + 100 * scale),
        (cx - 70 * scale, cy - 68 * scale),
        (cx - 40 * scale, cy - 116 * scale),
        (cx + 14 * scale, cy - 132 * scale),
        (cx + 74 * scale, cy - 98 * scale),
        (cx + 104 * scale, cy - 28 * scale),
        (cx + 78 * scale, cy + 6 * scale),
        (cx + 106 * scale, cy + 44 * scale),
        (cx + 72 * scale, cy + 80 * scale),
        (cx + 46 * scale, cy + 108 * scale),
        (cx + 42 * scale, cy + 148 * scale),
        (cx - 8 * scale, cy + 176 * scale),
        (cx - 50 * scale, cy + 164 * scale),
    ]
    draw.line(profile, fill=color, width=width, joint="curve")

    draw.arc(ellipse_bbox(cx - 8 * scale, cy - 2 * scale, 76 * scale, 86 * scale), start=235, end=58, fill=color, width=width)

    for node_x, node_y, node_r in [
        (cx - 140 * scale, cy - 70 * scale, 12),
        (cx - 150 * scale, cy - 16 * scale, 12),
        (cx - 128 * scale, cy + 50 * scale, 12),
        (cx - 8 * scale, cy - 42 * scale, 10),
        (cx - 6 * scale, cy + 14 * scale, 10),
        (cx - 4 * scale, cy + 80 * scale, 10),
    ]:
        draw.ellipse(ellipse_bbox(node_x, node_y, node_r, node_r), fill=color)

    draw.ellipse(ellipse_bbox(cx + 186, cy + 184, 16, 16), fill=accent, outline=(244, 240, 232, 230), width=4)


def main():
    base = Image.new("RGBA", (SIZE, SIZE), "#0B1830")
    draw_background(base)
    draw_badge(base)
    draw_agent_symbol(base)
    base.convert("RGB").save(OUTPUT, quality=96)
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()