# expect: ssrf line 6
import requests


def fetch(url):
    return requests.get(url).text
