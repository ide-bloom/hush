"""Generates docs/media/demo.gif: a placeholder until a real recording replaces it (see docs/media/README.md)."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent


def font(size: int) -> ImageFont.ImageFont:
    for name in ("CascadiaMono.ttf", "consola.ttf", "cour.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def main() -> None:
    lines = [
        ("PS> hush init", (230, 230, 240)),
        ("Windows Hello: Create your Hush vault...", (110, 200, 230)),
        ("YOUR RECOVERY KEY (shown once): XXXX-XXXX-...-XXXX", (230, 230, 240)),
        ("PS> hush scan", (230, 230, 240)),
        ("CRITICAL (2)  GitHub Personal access token  ghp_••••", (240, 110, 110)),
        ("PS> hush migrate", (230, 230, 240)),
        ("Migrated 2 secret(s) and updated 1 file(s).", (110, 210, 120)),
        ("PS> hush run -- npm run dev", (230, 230, 240)),
        ("", (0, 0, 0)),
        ("Demo recording placeholder - see docs/media/README.md", (150, 140, 255)),
    ]
    img = Image.new("RGB", (960, 420), (24, 22, 40))
    d = ImageDraw.Draw(img)
    d.rectangle((0, 0, 960, 34), fill=(44, 40, 72))
    for i, color in enumerate([(240, 90, 90), (240, 200, 80), (110, 200, 110)]):
        d.ellipse((14 + i * 22, 11, 26 + i * 22, 23), fill=color)
    f = font(20)
    for i, (text, color) in enumerate(lines):
        d.text((24, 52 + i * 34), text, fill=color, font=f)
    out = ROOT / "docs" / "media"
    out.mkdir(parents=True, exist_ok=True)
    img.save(out / "demo.gif")


if __name__ == "__main__":
    main()
