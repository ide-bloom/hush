"""Generates assets/hush.ico (and a PNG preview) from vector shapes. Run: python build/make-icon.py"""
from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
SIZE = 1024


def draw(accent=(124, 108, 255, 255)) -> Image.Image:
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # Rounded tile.
    d.rounded_rectangle((32, 32, SIZE - 32, SIZE - 32), radius=220, fill=(37, 33, 72, 255))
    # Shield.
    cx = SIZE // 2
    shield = [(cx, 170), (790, 270), (770, 560), (cx, 860), (254, 560), (234, 270)]
    d.polygon(shield, fill=accent)
    inner = [(cx, 230), (735, 315), (718, 548), (cx, 790), (306, 548), (289, 315)]
    d.polygon(inner, fill=(37, 33, 72, 255))
    # Keyhole.
    d.ellipse((cx - 90, 360, cx + 90, 540), fill=(240, 238, 255, 255))
    d.polygon([(cx - 55, 500), (cx + 55, 500), (cx + 80, 680), (cx - 80, 680)], fill=(240, 238, 255, 255))
    return img


def main() -> None:
    assets = ROOT / "assets"
    assets.mkdir(exist_ok=True)
    img = draw()
    img.resize((256, 256), Image.LANCZOS).save(assets / "hush.png")
    sizes = [(16, 16), (20, 20), (24, 24), (32, 32), (40, 40), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(assets / "hush.ico", sizes=sizes)
    # Tray icons: purple while locked, green while a session is unlocked.
    tray = [(16, 16), (20, 20), (24, 24), (32, 32), (40, 40), (48, 48), (64, 64)]
    draw().save(assets / "tray-locked.ico", sizes=tray)
    draw(accent=(63, 185, 80, 255)).save(assets / "tray-unlocked.ico", sizes=tray)


if __name__ == "__main__":
    main()
