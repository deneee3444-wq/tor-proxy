import os
import time
import requests
from flask import Flask, request, Response
from stem import Signal
from stem.control import Controller

app = Flask(__name__)

TOR_PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

TOR_CONTROL_PASSWORD = os.environ.get("TOR_CONTROL_PASSWORD", "changeme123")
API_TOKEN = "mySecretToken123"  # buraya kendi gizli tokenini yaz


def renew_tor_ip():
    """Tor'a NEWNYM sinyali gönderip yeni bir devre (yeni çıkış IP'si) ister."""
    with Controller.from_port(port=9051) as controller:
        controller.authenticate(password=TOR_CONTROL_PASSWORD)
        controller.signal(Signal.NEWNYM)
        wait_time = controller.get_newnym_wait()
    if wait_time > 0:
        time.sleep(wait_time)


@app.route("/")
def proxy():
    print(
        f"[REQUEST] ip={request.headers.get('X-Forwarded-For', request.remote_addr)} "
        f"url={request.args.get('url')!r} new_ip={request.args.get('new_ip')!r} "
        f"token_ok={not API_TOKEN or request.args.get('token') == API_TOKEN}",
        flush=True,
    )

    if API_TOKEN and request.args.get("token") != API_TOKEN:
        return "Unauthorized", 401

    url = request.args.get("url")
    if not url:
        return "Kullanım: /?url=https://example.com&new_ip=1&token=...", 400

    if request.args.get("new_ip") == "1":
        try:
            renew_tor_ip()
        except Exception as e:
            return f"Yeni IP alınamadı: {e}", 502

    try:
        upstream = requests.get(
            url,
            proxies=TOR_PROXIES,
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"},
        )
    except requests.exceptions.RequestException as e:
        return f"Tor üzerinden istek başarısız: {e}", 502

    excluded_headers = {"content-encoding", "transfer-encoding", "connection"}
    headers = [
        (k, v) for k, v in upstream.headers.items()
        if k.lower() not in excluded_headers
    ]

    return Response(upstream.content, status=upstream.status_code, headers=headers)


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
