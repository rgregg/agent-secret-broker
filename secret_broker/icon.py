"""The approved SB padlock icon, as PNG bytes loaded from secret_broker/assets/.

PNG is the 180x180 home-screen icon (apple-touch-icon), kept under its old name for the callers that
only need one icon; ui_theme.ICONS has every size. (tools/make_icon.py produced the previous generated
icon and is no longer used.)
"""
import pathlib

_DIR = pathlib.Path(__file__).resolve().parent / "assets"


def load(size):
    return (_DIR / f"sb-monogram-{size}.png").read_bytes()


PNG = load(180)
