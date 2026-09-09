import os
import re
import ssl
import time
import uuid
import threading
from urllib.parse import urljoin, quote, urlparse
import requests
from flask import Flask, request, Response, make_response
from flask_sock import Sock
import websocket as ws_client
from bs4 import BeautifulSoup
from stem import Signal
from stem.control import Controller

app = Flask(__name__)
sock = Sock(app)

TOR_PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

TOR_CONTROL_PASSWORD = os.environ.get("TOR_CONTROL_PASSWORD", "changeme123")
API_TOKEN = os.environ.get("API_TOKEN", "mySecretToken123")

SSL_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
)

SESSIONS = {}

REWRITE_ATTRS = [
    ("a", "href"),
    ("link", "href"),
    ("script", "src"),
    ("img", "src"),
    ("source", "src"),
    ("iframe", "src"),
    ("video", "src"),
    ("audio", "src"),
    ("embed", "src"),
    ("form", "action"),
]
CSS_URL_RE = re.compile(r"url\((['\"]?)(.*?)\1\)")
SKIP_SCHEMES = ("javascript:", "mailto:", "data:", "tel:", "#")


def renew_tor_ip():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate(password=TOR_CONTROL_PASSWORD)
        controller.signal(Signal.NEWNYM)
        wait_time = controller.get_newnym_wait()
    if wait_time > 0:
        time.sleep(wait_time)


def get_session():
    sid = request.cookies.get("psid")
    if not sid or sid not in SESSIONS:
        sid = uuid.uuid4().hex
        SESSIONS[sid] = requests.Session()
    return sid, SESSIONS[sid]


def proxy_link(absolute_url):
    return f"/browse?url={quote(absolute_url, safe='')}&token={API_TOKEN}"


def rewrite_html(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    for tag_name, attr in REWRITE_ATTRS:
        for el in soup.find_all(tag_name):
            val = el.get(attr)
            if not val or val.startswith(SKIP_SCHEMES):
                continue
            el[attr] = proxy_link(urljoin(base_url, val))

    for el in soup.find_all(["img", "source"]):
        if el.get("srcset"):
            parts = []
            for chunk in el["srcset"].split(","):
                bits = chunk.strip().split(" ")
                if bits and bits[0] and not bits[0].startswith(SKIP_SCHEMES):
                    bits[0] = proxy_link(urljoin(base_url, bits[0]))
                parts.append(" ".join(bits))
            el["srcset"] = ", ".join(parts)

    for el in soup.find_all(style=True):
        el["style"] = CSS_URL_RE.sub(
            lambda m: f"url({m.group(1)}{proxy_link(urljoin(base_url, m.group(2)))}{m.group(1)})",
            el["style"],
        )

    for el in soup.find_all("style"):
        if el.string:
            el.string.replace_with(
                CSS_URL_RE.sub(
                    lambda m: f"url({m.group(1)}{proxy_link(urljoin(base_url, m.group(2)))}{m.group(1)})",
                    el.string,
                )
            )

    for el in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
        content = el.get("content", "")
        m = re.search(r"url=(.+)", content, re.I)
        if m:
            el["content"] = re.sub(
                r"url=.+",
                f"url={proxy_link(urljoin(base_url, m.group(1).strip()))}",
                content,
                flags=re.I,
            )

    for el in soup.find_all("base"):
        el.decompose()

    return str(soup)


def rewrite_css(css_text, base_url):
    return CSS_URL_RE.sub(
        lambda m: f"url({m.group(1)}{proxy_link(urljoin(base_url, m.group(2)))}{m.group(1)})",
        css_text,
    )


@app.route("/browse", methods=["GET", "POST"])
def browse():
    if request.args.get("token") != API_TOKEN:
        return "Unauthorized", 401

    url = request.args.get("url")
    if not url:
        return "Kullanim: /browse?url=https://example.com&token=...", 400

    sid, sess = get_session()
    common_kwargs = dict(
        proxies=TOR_PROXIES,
        timeout=30,
        headers={"User-Agent": "Mozilla/5.0"},
        allow_redirects=True,
    )

    try:
        upstream = (
            sess.post(url, data=request.form, **common_kwargs)
            if request.method == "POST"
            else sess.get(url, **common_kwargs)
        )
    except requests.exceptions.RequestException as e:
        return f"Tor uzerinden istek basarisiz: {e}", 502

    content_type = upstream.headers.get("Content-Type", "")
    if "text/html" in content_type:
        body = rewrite_html(upstream.text, upstream.url)
        resp = make_response(body)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
    elif "text/css" in content_type:
        body = rewrite_css(upstream.text, upstream.url)
        resp = make_response(body)
        resp.headers["Content-Type"] = "text/css; charset=utf-8"
    else:
        resp = make_response(upstream.content)
        resp.headers["Content-Type"] = content_type

    resp.set_cookie("psid", sid, httponly=True, samesite="Lax")
    return resp


@app.route("/", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy():
    """Tüm HTTP/HTTPS isteklerini Tor üzerinden iletir."""
    if request.args.get("token") != API_TOKEN:
        return "Unauthorized", 401

    url = request.args.get("url")
    if not url:
        return "Kullanim: /?url=https://example.com&new_ip=1&token=...", 400

    if request.args.get("new_ip") == "1":
        try:
            renew_tor_ip()
        except Exception as e:
            return f"Yeni IP alinamadi: {e}", 502

    hop_by_hop = {
        "host",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
    forward_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in hop_by_hop
    }
    forward_headers["Host"] = urlparse(url).netloc

    try:
        upstream = requests.request(
            method=request.method,
            url=url,
            headers=forward_headers,
            data=request.get_data(),
            cookies=request.cookies,
            proxies=TOR_PROXIES,
            timeout=60,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as e:
        return f"Tor uzerinden istek basarisiz: {e}", 502

    excluded_headers = {"content-encoding", "transfer-encoding", "connection"}
    resp_headers = [
        (k, v)
        for k, v in upstream.headers.items()
        if k.lower() not in excluded_headers
    ]
    return Response(
        upstream.content, status=upstream.status_code, headers=resp_headers
    )


@sock.route("/ws")
def ws_proxy(client_ws):
    """Gelen WebSocket isteklerini Tor üzerinden UseAI sunucusuna köprüler."""
    if request.args.get("token") != API_TOKEN:
        client_ws.close(1008, "Unauthorized")
        return

    target_url = request.args.get("url")
    if not target_url:
        client_ws.close(1002, "Missing url")
        return

    extra_headers = [
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language: tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
        "Cache-Control: no-cache",
        "Pragma: no-cache",
    ]

    # Cloudflare başlığı sildiği için hem URL'deki cookies parametresini hem de başlığı kontrol et
    cookie_str = request.args.get("cookies") or request.headers.get("Cookie")
    if cookie_str:
        extra_headers.append(f"Cookie: {cookie_str}")

    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.set_ciphers(SSL_CIPHERS)
        upstream_ws = ws_client.create_connection(
            target_url,
            origin="https://use.ai",
            sslopt={"context": ssl_ctx},
            header=extra_headers,
            http_proxy_host="127.0.0.1",
            http_proxy_port=9050,
            proxy_type="socks5h",
            timeout=30,
        )
    except Exception as e:
        print(f"[WS ERROR] Upstream baglanti hatasi: {e}", flush=True)
        client_ws.close(1011, f"Upstream error: {e}")
        return

    active = True

    def upstream_to_client():
        nonlocal active
        try:
            while active:
                data = upstream_ws.recv()
                if not data:
                    break
                client_ws.send(data)
        except Exception:
            pass
        finally:
            active = False
            try:
                client_ws.close()
            except Exception:
                pass

    t = threading.Thread(target=upstream_to_client, daemon=True)
    t.start()

    try:
        while active:
            # 0.5s timeout ile dinle, kilitlenmeyi önle
            data = client_ws.receive(timeout=0.5)
            if data:
                upstream_ws.send(data)
    except Exception:
        pass
    finally:
        active = False
        try:
            upstream_ws.close()
        except Exception:
            pass
        t.join(timeout=2)


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
