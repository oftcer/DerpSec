"""Ponto de entrada do DerpSec."""
import sys


def main():
    try:
        from intercepta.gui import App
    except ImportError as exc:  # pragma: no cover
        print("Dependencia ausente: %s" % exc)
        print("Instale com: pip install cryptography")
        return 1
    App().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
