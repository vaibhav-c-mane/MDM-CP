"""Start the web app:  python run.py   then open http://127.0.0.1:8000

Options:  python run.py --port 9000 --no-browser
"""

import argparse
import threading
import webbrowser
from pathlib import Path

from backend.server import make_server

ROOT = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description="Digital Signature Verifier web app")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    args = parser.parse_args()

    if not (ROOT / "samples" / "samples.json").is_file():
        print("Setting up the demo certificate authority and sample files (first run only)...")
        from scripts.make_samples import main as make_samples

        make_samples()

    server = make_server(port=args.port)
    url = f"http://127.0.0.1:{args.port}"
    print(f"Digital Signature Verifier running at {url}  (press Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
