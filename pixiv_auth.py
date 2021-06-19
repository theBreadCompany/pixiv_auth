#!/usr/bin/env python

from json import loads
from re import search
from time import sleep
from base64 import urlsafe_b64encode
from hashlib import sha256
from secrets import token_urlsafe
from sys import exit
from urllib.parse import urlencode
from requests import post

from selenium.common.exceptions import WebDriverException
from selenium.webdriver import Chrome, Firefox, Edge
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

# Latest app version can be found using GET /v1/application-info/android
USER_AGENT = "PixivAndroidApp/5.0.234 (Android 11; Pixel 5)"
REDIRECT_URI = "https://app-api.pixiv.net/web/v1/users/auth/pixiv/callback"
LOGIN_URL = "https://app-api.pixiv.net/web/v1/login"
AUTH_TOKEN_URL = "https://oauth.secure.pixiv.net/auth/token"
CLIENT_ID = "MOBrBDS8blbauoSck0ZfDbtuzpyT"
CLIENT_SECRET = "lsACyCD94FhDUtGTXi3QzcFE2uU1hqtDaKeqrdwj"


def s256(data):
    """S256 transformation method."""

    return urlsafe_b64encode(sha256(data).digest()).rstrip(b"=").decode("ascii")


def oauth_pkce(transform):
    """Proof Key for Code Exchange by OAuth Public Clients (RFC7636)."""

    code_verifier = token_urlsafe(32)
    code_challenge = transform(code_verifier.encode("ascii"))

    return code_verifier, code_challenge


def return_auth_token_response(response):
    data = response.json()

    try:
        access_token = data.get("access_token")
        refresh_token = data.get("refresh_token")
        expires_in = data.get("expires_in")
        return ({"access_token": access_token,
                 "refresh_token": refresh_token,
                 "expires_in": expires_in})
    except KeyError:
        print("error:")
        print(data)
        exit(1)


def get_browser_with_caps():
    try:
        opts = ChromeOptions()
        opts.headless = True
        caps = DesiredCapabilities.CHROME
        caps["goog:loggingPrefs"] = {"performance": "ALL"}
        return Chrome(desired_capabilities=DesiredCapabilities.CHROME.copy(), options=opts)
    except WebDriverException:
        try:
            opts = FirefoxOptions
            opts.headless = True
            caps = DesiredCapabilities.FIREFOX
            caps["goog:loggingPrefs"] = {"performance": "ALL"}
            return Firefox(desired_capabilities=caps, options=opts)
        except WebDriverException:
            try:
                options = EdgeOptions
                options.headless = True
                caps = DesiredCapabilities.EDGE
                caps["goog:loggingPrefs"] = {"performance": "ALL"}
                return Edge(capabilities=caps, options=options)
            except WebDriverException:
                print("No browser found. Searching for [Chrome, Firefox, MS Edge].")
                exit(1)


def login(username, password):
    driver = get_browser_with_caps()

    code_verifier, code_challenge = oauth_pkce(s256)
    login_params = {
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "client": "pixiv-android",
    }

    driver.get(f"{LOGIN_URL}?{urlencode(login_params)}")

    username_box = driver.find_elements_by_class_name("input-field")[2].find_element_by_tag_name("input")
    username_box.send_keys(username)

    passwd_box = driver.find_elements_by_class_name("input-field")[3].find_element_by_tag_name("input")
    passwd_box.send_keys(password)

    driver.find_elements_by_class_name("signup-form__submit")[1].click()

    while True:
        # wait for login
        if driver.current_url[:40] == "https://accounts.pixiv.net/post-redirect":
            break
        sleep(1)

    # filter code url from performance logs
    code = None
    for row in driver.get_log('performance'):
        data = loads(row.get("message", {}))
        message = data.get("message", {})
        if message.get("method") == "Network.requestWillBeSent":
            url = message.get("params", {}).get("documentURL")
            if url[:8] == "pixiv://":
                code = search(r'code=([^&]*)', url).groups()[0]
                break

    driver.close()

    response = post(
        AUTH_TOKEN_URL,
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "code_verifier": code_verifier,
            "grant_type": "authorization_code",
            "include_policy": "true",
            "redirect_uri": REDIRECT_URI,
        },
        headers={"User-Agent": USER_AGENT},
    )

    return return_auth_token_response(response)