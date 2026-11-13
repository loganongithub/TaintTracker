# expect: ssrf line 6
import requests


def download(url):
    return requests.get(url).text
