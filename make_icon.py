"""Build letuc's application icon from the user's avatar.jpg.

The avatar is a portrait crop; a window icon wants a square, centered,
tight crop with the background flattened. We:

  1. load avatar.jpg
  2. detect the dominant background colour and flatten it
  3. centre-crop to square
  4. export 256x256 PNG (source for the .ico) plus 16/32/48/64 PNGs
  5. write assets/icon.png and assets/icon.ico

Run:  python make_icon.py
"""

import io
import os
import sys

from PIL import Image, ImageChops

SRC = r"D:\workspace\avatar.jpg"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "assets")
PNG_OUT = os.path.join(OUT_DIR, "letuc.png")
ICO_OUT = os.path.join(OUT_DIR, "letuc.ico")

SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def _background(img):
    """Pick the average colour in the border ring — usually the backdrop."""
    w, h = img.size
    ring = img.crop((0, 0, w, min(8, h))).convert("RGBA")
    ring.paste(img.crop((0, h - min(8, h), w, h)).convert("RGBA"), (0, 0))
    ring.paste(img.crop((0, 0, min(8, w), h)).convert("RGBA"), (0, 0))
    ring.paste(img.crop((w - min(8, w), 0, w, h)).convert("RGBA"), (0, 0))
    px = ring.resize((1, 1)).getpixel((0, 0))
    return px[:3]  # drop alpha; the caller adds it back


def main():
    if not os.path.exists(SRC):
        print("missing", SRC, file=sys.stderr)
        return 1
    os.makedirs(OUT_DIR, exist_ok=True)

    im = Image.open(SRC).convert("RGBA")
    bg = _background(im)

    # Flatten the backdrop so the portrait stands out against a solid field.
    flat = Image.new("RGBA", im.size, bg + (255,))
    flat.alpha_composite(im)

    w, h = flat.size
    side = min(w, h)
    left = (w - side) // 2
    top = (h - side) // 2
    square = flat.crop((left, top, left + side, top + side))

    # Round the corners slightly so it reads as an app glyph, not a photo.
    mask = Image.new("L", square.size, 0)
    r = int(side * 0.12)
    from PIL import ImageDraw
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle((0, 0, side, side), radius=r, fill=255)
    square.putalpha(mask)

    square.save(PNG_OUT)

    # Build a multi-res .ico. PIL writes the largest first, which is fine.
    square.resize((256, 256)).save(ICO_OUT, format="ICO",
                                    sizes=[(s, s) for s in SIZES])

    print("wrote", PNG_OUT, square.size)
    print("wrote", ICO_OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())