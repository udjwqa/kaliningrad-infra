"""
mini-КЛО config store. Читает apps.json из локальной директории.
Проксирует API compatible с main КЛО (config_store.get_app(), .resolve_proxy_key()).
"""
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("config")

CONFIG_DIR = Path(__file__).parent / "config"


@dataclass
class App:
    package_name: str = ""
    name: str = ""
    proxy_key: str = ""
    auth_token: str = ""
    target_url: str = ""
    safe_url: str = ""
    gcp_project_id: str = ""
    allowed_countries: List[str] = field(default_factory=list)
    excluded_countries: List[str] = field(default_factory=list)
    excluded_cities: List[str] = field(default_factory=list)
    require_integrity: bool = False
    cloak_consumed_enabled: bool = False
    direct_redirect: bool = False
    panic_mode: bool = False
    fraud_score_threshold: int = 90
    block_ipqs: bool = True
    block_vpn_asn: bool = True
    block_google_asn: bool = True
    block_pi_unevaluated_combo: bool = False
    disable_lang_check: bool = False
    white_flow_type: str = "safe_url"
    soft_pi_countries: List[str] = field(default_factory=list)
    soft_pi_countries_any_asn: List[str] = field(default_factory=list)
    asn_whitelist: List[int] = field(default_factory=list)
    cert_sha256: str = ""
    mini_server_id: Optional[str] = None


@dataclass
class Offers:
    targetUrl: str = ""
    safeUrl: str = ""


@dataclass
class Engine:
    scoreThreshold: int = 1


class ConfigStore:
    def __init__(self):
        self.apps: List[App] = []
        self.debug_allow: dict = {"ips": [], "instances": []}
        self._proxy_key_to_pkg = {}
        self._pkg_to_app = {}
        self.offers = Offers()
        self.engine = Engine()

    def reload(self):
        """Читает apps.json из локальной папки."""
        apps_path = CONFIG_DIR / "apps.json"
        if not apps_path.exists():
            logger.error(f"apps.json not found at {apps_path}")
            self.apps = []
            return

        try:
            data = json.load(open(apps_path))
        except Exception as e:
            logger.error(f"Failed to parse apps.json: {e}")
            return

        self.apps = []
        self._proxy_key_to_pkg = {}
        self._pkg_to_app = {}

        for raw in data:
            # Convert dict → App dataclass (только known fields)
            kwargs = {}
            for f_name in App.__dataclass_fields__:
                if f_name in raw:
                    kwargs[f_name] = raw[f_name]
            app = App(**kwargs)
            self.apps.append(app)
            if app.proxy_key:
                self._proxy_key_to_pkg[app.proxy_key] = app.package_name
            self._pkg_to_app[app.package_name] = app

        logger.info(f"config: loaded {len(self.apps)} apps")
        self._load_debug()

    def get_app(self, package_name: str) -> Optional[App]:
        return self._pkg_to_app.get(package_name)

    def resolve_proxy_key(self, proxy_key: str) -> Optional[dict]:
        pkg = self._proxy_key_to_pkg.get(proxy_key)
        if not pkg:
            return None
        return {"package_name": pkg}

    def is_debug(self, ip: str = "", instance_id: str = "") -> bool:
        """Debug whitelist — force grey for IP/instance in debug_allow.json.
        2026-07-14: aligned с main КЛО (config.py:160-167)."""
        if ip and ip in self.debug_allow.get("ips", []):
            return True
        if instance_id and instance_id in self.debug_allow.get("instances", []):
            return True
        return False

    def _load_debug(self):
        """Load debug_allow.json from CONFIG_DIR (synced from main КЛО)."""
        try:
            from pathlib import Path
            import json as _json
            debug_file = Path(__file__).parent / "config" / "debug_allow.json"
            if debug_file.exists():
                d = _json.loads(debug_file.read_text(encoding="utf-8"))
                self.debug_allow = {
                    "ips": list(d.get("ips", [])),
                    "instances": list(d.get("instances", [])),
                }
            else:
                self.debug_allow = {"ips": [], "instances": []}
        except Exception:
            self.debug_allow = {"ips": [], "instances": []}


config_store = ConfigStore()
