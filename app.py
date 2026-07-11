import os
import re
import time
import uuid
import requests
from urllib.parse import urljoin, quote
from flask import Flask, request, Response, make_response
from bs4 import BeautifulSoup
from stem import Signal
from stem.control import Controller

app = Flask(__name__)

TOR_PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

TOR_CONTROL_PASSWORD = os.environ.get("TOR_CONTROL_PASSWORD", "changeme123")
API_TOKEN = "mySecretToken123"  # buraya kendi gizli tokenini yaz

# session_id -> requests.Session (hedef sitenin cookie/oturum bilgisini taşımak icin)
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
    """Tor'a NEWNYM sinyali gonderip yeni bir devre (yeni cikis IP'si) ister."""
    with Controller.from_port(port=9051) as controller:
        controller.authenticate(password=TOR_CONTROL_PASSWORD)
        controller.signal(Signal.NEWNYM)
        wait_time = controller.get_newnym_wait()
    if wait_time > 0:
        time.sleep(wait_time)


def get_session():
    """Her tarayici icin ayri bir requests.Session tutar, boylece hedef sitenin
    login/cookie/session bilgisi istekler arasinda korunur."""
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
            absolute = urljoin(base_url, val)
            el[attr] = proxy_link(absolute)

    # srcset: birden fazla url virgulle ayrilmis olabilir (img/source)
    for el in soup.find_all(["img", "source"]):
        if el.get("srcset"):
            parts = []
            for chunk in el["srcset"].split(","):
                bits = chunk.strip().split(" ")
                if bits and bits[0] and not bits[0].startswith(SKIP_SCHEMES):
                    bits[0] = proxy_link(urljoin(base_url, bits[0]))
                parts.append(" ".join(bits))
            el["srcset"] = ", ".join(parts)

    # inline style="...url(...)..."
    for el in soup.find_all(style=True):
        el["style"] = CSS_URL_RE.sub(
            lambda m: f"url({m.group(1)}{proxy_link(urljoin(base_url, m.group(2)))}{m.group(1)})",
            el["style"],
        )

    # <style>...</style> bloklari
    for el in soup.find_all("style"):
        if el.string:
            el.string.replace_with(
                CSS_URL_RE.sub(
                    lambda m: f"url({m.group(1)}{proxy_link(urljoin(base_url, m.group(2)))}{m.group(1)})",
                    el.string,
                )
            )

    # meta refresh yonlendirmesi
    for el in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
        content = el.get("content", "")
        m = re.search(r"url=(.+)", content, re.I)
        if m:
            absolute = urljoin(base_url, m.group(1).strip())
            el["content"] = re.sub(r"url=.+", f"url={proxy_link(absolute)}", content, flags=re.I)

    # base tag'i kaldiriyoruz; linkleri zaten kendimiz mutlaklastirdik
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
        if request.method == "POST":
            upstream = sess.post(url, data=request.form, **common_kwargs)
        else:
            upstream = sess.get(url, **common_kwargs)
    except requests.exceptions.RequestException as e:
        return f"Tor uzerinden istek basarisiz: {e}", 502

    content_type = upstream.headers.get("Content-Type", "")
    final_url = upstream.url  # redirect sonrasi gercek adres

    if "text/html" in content_type:
        body = rewrite_html(upstream.text, final_url)
        resp = make_response(body)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
    elif "text/css" in content_type:
        body = rewrite_css(upstream.text, final_url)
        resp = make_response(body)
        resp.headers["Content-Type"] = "text/css; charset=utf-8"
    else:
        resp = make_response(upstream.content)
        resp.headers["Content-Type"] = content_type

    resp.set_cookie("psid", sid, httponly=True, samesite="Lax")
    return resp


@app.route("/")
def proxy():
    """Ham API/JSON cekmek icin basit endpoint (rewriting yapmaz)."""
    print(
        f"[REQUEST] ip={request.headers.get('X-Forwarded-For', request.remote_addr)} "
        f"url={request.args.get('url')!r} new_ip={request.args.get('new_ip')!r} "
        f"token_ok={request.args.get('token') == API_TOKEN}",
        flush=True,
    )

    if request.args.get("token") != API_TOKEN:
        return "Unauthorized", 401

    url = request.args.get("url")
    if not url:
        return "Kullanim: /?url=https://example.com&new_ip=1&token=...  (tam site gezmek icin /browse kullan)", 400

    if request.args.get("new_ip") == "1":
        try:
            renew_tor_ip()
        except Exception as e:
            return f"Yeni IP alinamadi: {e}", 502

    try:
        upstream = requests.get(
            url, proxies=TOR_PROXIES, timeout=30,
            headers={"User-Agent": "Mozilla/5.0"},
        )
    except requests.exceptions.RequestException as e:
        return f"Tor uzerinden istek basarisiz: {e}", 502

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
