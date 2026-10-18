import socket
import http.client as hc
import subprocess as sp
from os import open as os_open
from httpx import Client as HttpxClient
import requests
import urllib3


def send(host: str) -> None:
    conn = hc.HTTPSConnection(host)
    conn.request("GET", "/v1/x")
    s = socket.socket()
    s.connect((host, 443))


class Uploader:
    def __init__(self) -> None:
        self.pool = urllib3.PoolManager()

    def upload(self, url: str) -> None:
        with HttpxClient() as c:
            c.post(url)
        self.helper()

    def helper(self) -> None:
        r = requests.get("https://example.com/")
        r.json()


def run() -> None:
    sp.run(["true"])
    fd = os_open("/tmp/x", 0)
    with open("/tmp/y") as fh:
        fh.read()


def shadowed(requests) -> None:
    requests.get("x")


def dynamic(name: str) -> None:
    mod = __import__(name)
    getattr(mod, "get")("https://hidden.example/")
