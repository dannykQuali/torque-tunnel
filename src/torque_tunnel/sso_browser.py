"""Cisco ID (SSO) sign-in via a temporary DevTools-controlled browser.

Torque's Cisco ID login is an OIDC flow whose redirect_uri is hardcoded to
the Torque host (/api/accounts/idp-callback) and pre-registered with Cisco's
IdP, so a localhost callback can never receive the result. The token is
delivered only to a browser on the Torque origin: the backend sets a one-shot
non-HttpOnly 'loginResponse' cookie (or 'loginMultiAccountResponse' for users
with several accounts) and redirects to the Torque UI, which moves it into
localStorage.

To automate this, we launch a Chromium-based browser (Edge/Chrome) with a
throwaway profile and remote debugging enabled, navigate it to Torque's
idp_login endpoint, and poll Torque-origin pages via the Chrome DevTools
Protocol until the token appears in localStorage or the cookie. The browser
window is then closed and the temporary profile deleted.
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Optional

import aiohttp
import httpx

CISCO_IDP_LOGIN_PATH = "/api/accounts/idp_login/Cisco"

_LOGIN_RESPONSE_KEY = "loginResponse"
_MULTI_ACCOUNT_KEY = "loginMultiAccountResponse"

# JS evaluated on Torque-origin pages to fetch the SSO result. The Torque SPA
# moves the one-shot loginResponse cookie into localStorage on boot; we check
# both to close the race window between the IdP redirect and the SPA boot.
_HARVEST_EXPRESSION = (
    "JSON.stringify({"
    "lr: localStorage.getItem('loginResponse'),"
    "lmar: localStorage.getItem('loginMultiAccountResponse'),"
    "cookie: document.cookie})"
)

# UI routes Torque redirects to when the IdP flow fails
_ERROR_PATHS = ("/ssoerror", "/error")


class SsoLoginError(Exception):
    """Raised when the SSO browser flow cannot be started or fails."""


# Executable basenames of Chromium-based browsers that speak the DevTools protocol
_CHROMIUM_EXE_NAMES = {
    "msedge.exe", "chrome.exe", "brave.exe", "vivaldi.exe", "opera.exe",
    "opera_gx.exe", "chromium.exe",
    "msedge", "chrome", "google-chrome", "google-chrome-stable", "brave",
    "brave-browser", "microsoft-edge", "vivaldi", "opera", "chromium",
    "chromium-browser",
}


def _is_chromium_exe(path: str) -> bool:
    return Path(path).name.lower() in _CHROMIUM_EXE_NAMES


def _extract_exe_from_command(command: str) -> Optional[str]:
    """Extract the executable path from a shell-open command like '"C:\\...\\brave.exe" %1'."""
    command = (command or "").strip()
    if not command:
        return None
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end > 0 else None
    return command.split()[0]


def _windows_https_command() -> Optional[str]:
    """Read the shell-open command of the user's default https handler from the registry."""
    import winreg
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice",
    ) as key:
        prog_id = winreg.QueryValueEx(key, "ProgId")[0]
    with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, prog_id + r"\shell\open\command") as key:
        return winreg.QueryValueEx(key, None)[0]


def _macos_default_chromium() -> Optional[str]:
    import plistlib
    plist = (Path.home() / "Library" / "Preferences" / "com.apple.launchservices"
             / "com.apple.launchservices.secure.plist")
    try:
        with open(plist, "rb") as f:
            data = plistlib.load(f)
    except OSError:
        return None
    bundle_id = ""
    for handler in data.get("LSHandlers", []):
        if handler.get("LSHandlerURLScheme") == "https":
            bundle_id = (handler.get("LSHandlerRoleAll") or "").lower()
            break
    apps = {
        "com.google.chrome": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "com.microsoft.edgemac": "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "com.brave.browser": "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        "com.vivaldi.vivaldi": "/Applications/Vivaldi.app/Contents/MacOS/Vivaldi",
        "com.operasoftware.opera": "/Applications/Opera.app/Contents/MacOS/Opera",
        "org.chromium.chromium": "/Applications/Chromium.app/Contents/MacOS/Chromium",
    }
    path = apps.get(bundle_id)
    return path if path and Path(path).exists() else None


def _linux_default_chromium() -> Optional[str]:
    desktop = ""
    for cmd in (
        ["xdg-settings", "get", "default-web-browser"],
        ["xdg-mime", "query", "default", "x-scheme-handler/https"],
    ):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except Exception:
            continue
        desktop = (result.stdout or "").strip()
        if desktop:
            break
    if not desktop:
        return None
    base = desktop[:-len(".desktop")] if desktop.endswith(".desktop") else desktop
    for name in (base, base.replace("-stable", "")):
        if name.lower() in _CHROMIUM_EXE_NAMES:
            found = shutil.which(name)
            if found:
                return found
    return None


def find_default_chromium_browser() -> Optional[str]:
    """Return the OS-default browser executable, if it is Chromium-based."""
    try:
        if sys.platform == "win32":
            command = _windows_https_command()
        elif sys.platform == "darwin":
            return _macos_default_chromium()
        else:
            return _linux_default_chromium()
    except Exception:
        return None
    exe = _extract_exe_from_command(command)
    if exe and _is_chromium_exe(exe) and Path(exe).exists():
        return exe
    return None


def _candidate_browser_paths() -> list:
    """Well-known install locations of Chromium-based browsers per platform."""
    paths = []
    if sys.platform == "win32":
        for env in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            base = os.environ.get(env)
            if not base:
                continue
            paths.append(os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"))
            paths.append(os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"))
            paths.append(os.path.join(base, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"))
            paths.append(os.path.join(base, "Vivaldi", "Application", "vivaldi.exe"))
        local = os.environ.get("LOCALAPPDATA")
        if local:
            paths.append(os.path.join(local, "Programs", "Opera", "opera.exe"))
    elif sys.platform == "darwin":
        paths.extend([
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/Applications/Vivaldi.app/Contents/MacOS/Vivaldi",
            "/Applications/Opera.app/Contents/MacOS/Opera",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ])
    return paths


def find_chromium_browser() -> Optional[str]:
    """Locate a Chromium-based browser executable (Edge/Chrome/Brave/Vivaldi/Opera/Chromium).

    Order: TORQUE_TUNNEL_SSO_BROWSER env override → the OS-default browser when
    it is Chromium-based → well-known install locations → PATH lookup.
    """
    override = os.environ.get("TORQUE_TUNNEL_SSO_BROWSER")
    if override and Path(override).exists():
        return override
    default = find_default_chromium_browser()
    if default:
        return default
    for path in _candidate_browser_paths():
        if Path(path).exists():
            return path
    for name in ("msedge", "chrome", "google-chrome", "brave", "brave-browser",
                 "vivaldi", "opera", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _default_launcher(cmd):
    """Launch the browser process, detached from our stdio."""
    return subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _parse_cookies(cookie_header: str) -> dict:
    """Parse a document.cookie string into a dict (values URL-decoded)."""
    result = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        result[key.strip()] = urllib.parse.unquote(value.strip())
    return result


def _try_json(raw):
    """Parse JSON that may be URL-encoded (cookie values often are)."""
    for candidate in (raw, urllib.parse.unquote(raw)):
        try:
            return json.loads(candidate)
        except (TypeError, ValueError):
            continue
    return None


# Hosts where Cisco ID sign-in must not be offered even if the backend
# responds to the probe (the public Quali SaaS portal).
_CISCO_SSO_DISABLED_HOSTS = {"portal.qtorque.io"}


async def probe_cisco_sso(torque_url: str) -> bool:
    """Check whether a Torque instance supports Cisco ID login.

    Calls the idp_login endpoint without following redirects; support means a
    redirect to the IdP carrying a non-empty client_id. Denylisted hosts are
    rejected without any network call.
    """
    if not torque_url:
        return False
    try:
        host = (urllib.parse.urlsplit(torque_url).hostname or "").lower()
    except ValueError:
        return False
    if host in _CISCO_SSO_DISABLED_HOSTS:
        return False
    url = torque_url.rstrip("/") + CISCO_IDP_LOGIN_PATH
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            resp = await client.get(url)
    except Exception:
        return False
    if resp.status_code not in (301, 302, 303, 307, 308):
        return False
    location = resp.headers.get("location", "")
    try:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    except ValueError:
        return False
    return bool(query.get("client_id", [""])[0])


class CiscoSsoSession:
    """One Cisco ID sign-in attempt through a temporary browser.

    Lifecycle: construct → await start() → poll .status until it leaves
    'pending' → read .token (single account) or .accounts (multi account).
    Call cancel() to abort. The browser and its temp profile are cleaned up
    automatically on success, error, or cancel.
    """

    def __init__(
        self,
        torque_url: str,
        *,
        browser_path: Optional[str] = None,
        launcher=None,
        poll_interval: float = 1.0,
        timeout: float = 600.0,
        devtools_wait: float = 30.0,
    ):
        self.torque_url = (torque_url or "").rstrip("/")
        self.status = "pending"  # pending | success | error | cancelled
        self.error: Optional[str] = None
        self.token: Optional[str] = None  # single-account access_token
        self.accounts: Optional[dict] = None  # multi-account: alias -> TokenResponse
        self._browser_path = browser_path
        self._launcher = launcher or _default_launcher
        self._poll_interval = poll_interval
        self._timeout = timeout
        self._devtools_wait = devtools_wait
        self._proc = None
        self._task: Optional[asyncio.Task] = None
        self._user_data_dir: Optional[str] = None

    async def start(self) -> None:
        """Launch the browser and begin watching for the token.

        Raises SsoLoginError if no browser is available or launch fails.
        """
        browser = self._browser_path or find_chromium_browser()
        if not browser:
            raise SsoLoginError(
                "No Chromium-based browser (Microsoft Edge / Google Chrome) was found. "
                "Set the TORQUE_TUNNEL_SSO_BROWSER environment variable to your browser "
                "executable, or sign in on the Torque website and paste a token instead."
            )
        self._user_data_dir = tempfile.mkdtemp(prefix="torque-tunnel-sso-")
        cmd = [
            browser,
            f"--user-data-dir={self._user_data_dir}",
            "--remote-debugging-port=0",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-sync",
            "--disable-session-crashed-bubble",
            "--new-window",
            f"{self.torque_url}{CISCO_IDP_LOGIN_PATH}",
        ]
        try:
            self._proc = self._launcher(cmd)
        except Exception as e:
            await self._remove_profile_dir()
            raise SsoLoginError(f"Failed to launch browser: {e}") from e
        self._task = asyncio.create_task(self._run())

    async def wait_done(self) -> None:
        """Wait for the watcher task (including cleanup) to finish."""
        if self._task:
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def cancel(self) -> None:
        """Abort the sign-in: stop watching, close the browser, delete the profile."""
        task = self._task
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        if self.status == "pending":
            self.status = "cancelled"
        self._terminate_browser()
        await self._remove_profile_dir()

    # -- Internal --

    async def _run(self) -> None:
        try:
            port = await self._wait_for_devtools_port()
            await self._poll_for_token(port)
        except SsoLoginError as e:
            self._set_error(str(e))
        except Exception as e:
            self._set_error(f"Cisco ID sign-in failed: {e}")
        finally:
            self._terminate_browser()
            await self._remove_profile_dir()

    def _set_error(self, message: str) -> None:
        if self.status == "pending":
            self.status = "error"
            self.error = message

    def _browser_exited(self) -> bool:
        return self._proc is not None and self._proc.poll() is not None

    async def _wait_for_devtools_port(self) -> int:
        """Wait for the browser to write its DevToolsActivePort file."""
        marker = Path(self._user_data_dir) / "DevToolsActivePort"
        deadline = time.monotonic() + self._devtools_wait
        while True:
            if self._browser_exited():
                raise SsoLoginError("Browser window was closed before sign-in completed")
            try:
                return int(marker.read_text(encoding="ascii").splitlines()[0])
            except (OSError, ValueError, IndexError):
                pass
            if time.monotonic() > deadline:
                raise SsoLoginError("Browser did not expose a DevTools endpoint in time")
            await asyncio.sleep(0.1)

    async def _poll_for_token(self, port: int) -> None:
        deadline = time.monotonic() + self._timeout
        async with aiohttp.ClientSession() as http:
            while True:
                if self._browser_exited():
                    raise SsoLoginError("Browser window was closed before sign-in completed")
                if time.monotonic() > deadline:
                    raise SsoLoginError(f"Cisco ID sign-in timed out after {int(self._timeout)}s")
                for target in await self._list_page_targets(http, port):
                    url = target.get("url", "")
                    if not self._is_torque_origin(url):
                        continue
                    if urllib.parse.urlsplit(url).path in _ERROR_PATHS:
                        raise SsoLoginError(
                            "Torque reported that the SSO sign-in failed (error page shown in browser)"
                        )
                    ws_url = target.get("webSocketDebuggerUrl")
                    if ws_url and await self._harvest_from_page(http, ws_url):
                        return
                await asyncio.sleep(self._poll_interval)

    def _is_torque_origin(self, url: str) -> bool:
        try:
            torque = urllib.parse.urlsplit(self.torque_url)
            page = urllib.parse.urlsplit(url)
        except ValueError:
            return False
        return (page.scheme, page.netloc.lower()) == (torque.scheme, torque.netloc.lower())

    async def _list_page_targets(self, http: aiohttp.ClientSession, port: int) -> list:
        try:
            async with http.get(
                f"http://127.0.0.1:{port}/json/list",
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                targets = await resp.json()
        except Exception:
            return []
        if not isinstance(targets, list):
            return []
        return [t for t in targets if isinstance(t, dict) and t.get("type") == "page"]

    async def _harvest_from_page(self, http: aiohttp.ClientSession, ws_url: str) -> bool:
        """Evaluate the harvest expression in a page; returns True on success."""
        try:
            return await asyncio.wait_for(self._harvest_inner(http, ws_url), timeout=10.0)
        except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
            return False

    async def _harvest_inner(self, http: aiohttp.ClientSession, ws_url: str) -> bool:
        async with http.ws_connect(ws_url) as ws:
            await ws.send_json({
                "id": 1,
                "method": "Runtime.evaluate",
                "params": {"expression": _HARVEST_EXPRESSION, "returnByValue": True},
            })
            async for msg in ws:
                if msg.type != aiohttp.WSMsgType.TEXT:
                    break
                data = json.loads(msg.data)
                if data.get("id") == 1:
                    value = (((data.get("result") or {}).get("result")) or {}).get("value")
                    return self._consume_payload(value)
        return False

    def _consume_payload(self, value) -> bool:
        """Extract token(s) from the harvest payload; sets success state."""
        if not value:
            return False
        try:
            payload = json.loads(value)
        except (TypeError, ValueError):
            return False
        cookies = _parse_cookies(payload.get("cookie") or "")
        multi_raw = payload.get("lmar") or cookies.get(_MULTI_ACCOUNT_KEY)
        single_raw = payload.get("lr") or cookies.get(_LOGIN_RESPONSE_KEY)

        if multi_raw:
            accounts = _try_json(multi_raw)
            if isinstance(accounts, dict) and any(
                isinstance(v, dict) and v.get("access_token") for v in accounts.values()
            ):
                self.accounts = accounts
                self.status = "success"
                return True
        if single_raw:
            token_data = _try_json(single_raw)
            if isinstance(token_data, dict) and token_data.get("access_token"):
                self.token = token_data["access_token"]
                self.status = "success"
                return True
        return False

    def _terminate_browser(self) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
        except Exception:
            pass

    async def _remove_profile_dir(self) -> None:
        """Delete the throwaway browser profile (retries for Windows file locks)."""
        udd = self._user_data_dir
        if not udd:
            return
        for _ in range(5):
            shutil.rmtree(udd, ignore_errors=True)
            if not os.path.exists(udd):
                return
            await asyncio.sleep(0.5)
        # Best effort — an undeletable leftover in %TEMP% is acceptable
