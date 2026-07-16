import json
import os
import uuid
import secrets
from pathlib import Path
from datetime import datetime, timezone
from models import EngineConfig, OfferConfig, AppEntry

BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config.json"
OFFERS_FILE = BASE_DIR / "offers.json"
APPS_FILE = BASE_DIR / "config" / "apps.json"
PROXY_KEYS_FILE = BASE_DIR / "config" / "proxy_keys.json"
DEBUG_FILE = BASE_DIR / "config" / "debug_allow.json"
MOBILE_ASN_FILE = BASE_DIR / "config" / "mobile_asn_whitelist.json"
GOOGLE_ASN_FILE = BASE_DIR / "config" / "google_asn_blocklist.json"
VPN_ASN_FILE = BASE_DIR / "config" / "vpn_asn_blocklist.json"


class ConfigStore:
    def __init__(self):
        self.engine: EngineConfig = EngineConfig()
        self.offers: OfferConfig = OfferConfig()
        self.apps: list[AppEntry] = []
        self.proxy_keys: dict[str, dict] = {}
        self.debug_allow: dict[str, list] = {"ips": [], "instances": []}
        # Smart Soft PI: ASN мобильных операторов NG/CI/SN и hard-block Google
        self.mobile_asn_whitelist: dict[str, list[int]] = {}
        self.google_asn_blocklist: set[int] = set()
        # VPN/datacenter ASN hard-block (commercial VPN providers + хостеры).
        # 2026-06-21: добавлено после Sisal-incident — модер пробил через M247 VPN.
        self.vpn_asn_blocklist: set[int] = set()

    def load(self):
        if CONFIG_FILE.exists():
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            self.engine = EngineConfig(**data)
        else:
            self.save_engine()

        if OFFERS_FILE.exists():
            data = json.loads(OFFERS_FILE.read_text(encoding="utf-8"))
            self.offers = OfferConfig(**data)
        else:
            self.save_offers()

        self._load_apps()
        self._load_proxy_keys()
        self._load_debug()
        self._load_mobile_asn()
        self._load_google_asn()
        self._load_vpn_asn()

    def _load_mobile_asn(self):
        if MOBILE_ASN_FILE.exists():
            try:
                d = json.loads(MOBILE_ASN_FILE.read_text(encoding="utf-8"))
                # Только страны-ключи с числовыми списками (игнорим _comment, _operators)
                self.mobile_asn_whitelist = {
                    k: [int(x) for x in v]
                    for k, v in d.items()
                    if not k.startswith("_") and isinstance(v, list)
                }
            except Exception:
                self.mobile_asn_whitelist = {}
        else:
            self.mobile_asn_whitelist = {}

    def _load_google_asn(self):
        if GOOGLE_ASN_FILE.exists():
            try:
                d = json.loads(GOOGLE_ASN_FILE.read_text(encoding="utf-8"))
                self.google_asn_blocklist = set(int(x) for x in d.get("hard_block", []))
            except Exception:
                self.google_asn_blocklist = set()
        else:
            self.google_asn_blocklist = set()

    def _load_vpn_asn(self):
        """VPN/datacenter ASN hard-block (M247, NordVPN, Surfshark, Vultr, OVH, и др.).
        2026-06-21: добавлено для protected apps (require_integrity=True + block_vpn_asn=True)."""
        if VPN_ASN_FILE.exists():
            try:
                d = json.loads(VPN_ASN_FILE.read_text(encoding="utf-8"))
                self.vpn_asn_blocklist = set(int(x) for x in d.get("hard_block", []))
            except Exception:
                self.vpn_asn_blocklist = set()
        else:
            self.vpn_asn_blocklist = set()

    def save_engine(self):
        CONFIG_FILE.write_text(
            self.engine.model_dump_json(indent=2), encoding="utf-8"
        )

    def save_offers(self):
        OFFERS_FILE.write_text(
            self.offers.model_dump_json(indent=2), encoding="utf-8"
        )

    def update_engine(self, config: EngineConfig):
        self.engine = config
        self.save_engine()

    def update_offers(self, config: OfferConfig):
        self.offers = config
        self.save_offers()

    def _load_apps(self):
        APPS_FILE.parent.mkdir(parents=True, exist_ok=True)
        if APPS_FILE.exists():
            data = json.loads(APPS_FILE.read_text(encoding="utf-8"))
            self.apps = [AppEntry(**a) for a in data]
        else:
            self.apps = []
            self._save_apps()

    def _save_apps(self):
        APPS_FILE.parent.mkdir(parents=True, exist_ok=True)
        APPS_FILE.write_text(
            json.dumps([a.model_dump() for a in self.apps], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _load_proxy_keys(self):
        if PROXY_KEYS_FILE.exists():
            self.proxy_keys = json.loads(PROXY_KEYS_FILE.read_text(encoding="utf-8"))
        else:
            self.proxy_keys = {}

    def _save_proxy_keys(self):
        PROXY_KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = PROXY_KEYS_FILE.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(self.proxy_keys, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        os.replace(tmp, PROXY_KEYS_FILE)

    def _load_debug(self):
        if DEBUG_FILE.exists():
            try:
                d = json.loads(DEBUG_FILE.read_text(encoding="utf-8"))
                self.debug_allow = {
                    "ips": list(d.get("ips", [])),
                    "instances": list(d.get("instances", [])),
                }
            except Exception:
                self.debug_allow = {"ips": [], "instances": []}
        else:
            self.debug_allow = {"ips": [], "instances": []}

    def _save_debug(self):
        DEBUG_FILE.parent.mkdir(parents=True, exist_ok=True)
        DEBUG_FILE.write_text(
            json.dumps(self.debug_allow, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def is_debug(self, ip: str = "", instance_id: str = "") -> bool:
        """Тест-режим: запросы с whitelist IP/instance проходят без PI-гейта (force grey).
        Точечная дырка под тест дева — модеры с другими ip/instance не затрагиваются."""
        if ip and ip in self.debug_allow.get("ips", []):
            return True
        if instance_id and instance_id in self.debug_allow.get("instances", []):
            return True
        return False

    def get_debug(self) -> dict:
        return {
            "ips": list(self.debug_allow.get("ips", [])),
            "instances": list(self.debug_allow.get("instances", [])),
        }

    def set_debug(self, ips: list, instances: list):
        clean_ips = [s.strip() for s in (ips or []) if isinstance(s, str) and s.strip()]
        clean_inst = [s.strip() for s in (instances or []) if isinstance(s, str) and s.strip()]
        self.debug_allow = {"ips": clean_ips, "instances": clean_inst}
        self._save_debug()

    def resolve_proxy_key(self, key: str) -> dict | None:
        return self.proxy_keys.get(key)

    def get_proxy_key_for_package(self, package_name: str) -> str:
        for key, data in self.proxy_keys.items():
            if data.get("package_name") == package_name:
                return key
        return ""

    def add_proxy_key(self, key: str, package_name: str, name: str):
        self.proxy_keys[key] = {"package_name": package_name, "name": name}
        self._save_proxy_keys()

    def remove_proxy_key_for_package(self, package_name: str):
        keys = [k for k, v in self.proxy_keys.items() if v.get("package_name") == package_name]
        for k in keys:
            del self.proxy_keys[k]
        if keys:
            self._save_proxy_keys()

    @staticmethod
    def generate_proxy_key() -> str:
        return "pk_" + secrets.token_hex(16)

    @staticmethod
    def generate_auth_token() -> str:
        return secrets.token_hex(6)

    def get_app(self, package_name: str) -> AppEntry | None:
        for app in self.apps:
            if app.package_name == package_name:
                return app
        return None

    def get_app_by_id(self, app_id: str) -> AppEntry | None:
        for app in self.apps:
            if app.id == app_id:
                return app
        return None

    def add_app(self, name: str, package_name: str, cert_sha256: str = "",
                gcp_project_id: str = "", safe_url: str = "", target_url: str = "",
                white_flow_type: str = "redirect_safe",
                excluded_countries: list = None,
                excluded_cities: list = None,
                allowed_countries: list = None,
                disable_lang_check: bool = False,
                require_integrity: bool = False,
                block_v2_gateway: bool = False,
                # P1-9 (2026-06-21): добавлены — раньше silently drops при CREATE,
                # из-за чего новые apps создавались без Smart Soft PI настроек для NG/CI/SN
                # и без Google ASN hard-kill (block_google_asn=True по умолчанию = защита есть).
                soft_pi_countries: list = None,
                # NG-relax (2026-06-21): per-country exemption от mobile_asn_whitelist check.
                soft_pi_countries_any_asn: list = None,
                block_google_asn: bool = True,
                # VPN-blocklist (2026-06-21): hard-block commercial VPN/datacenter ASN
                # для protected apps. Default True — это generic защита.
                block_vpn_asn: bool = True,
                # 2026-06-22: PI v3 advanced — UNEVALUATED combo hard-kill on first_init.
                block_pi_unevaluated_combo: bool = True,
                # 2026-06-22: IPQS hard-kill для protected apps (fail-open if no key).
                block_ipqs: bool = True,
                # P1-1 (2026-06-21): cloak_consumed одноразовость per app.
                cloak_consumed_enabled: bool = False,
                proxy_key: str = "", auth_token: str = "",
                # DAL-alignment (2026-07-09): mini-server URL + path из assetlinks.json.
                endpoint: str = "",
                sdk_path: str = "/init") -> AppEntry:
        # Автоген ключа/токена, если не заданы вручную
        proxy_key = proxy_key.strip() or self.generate_proxy_key()
        auth_token = auth_token.strip() or self.generate_auth_token()

        app = AppEntry(
            id=str(uuid.uuid4()),
            name=name,
            package_name=package_name,
            cert_sha256=cert_sha256,
            gcp_project_id=gcp_project_id,
            safe_url=safe_url,
            target_url=target_url,
            white_flow_type=white_flow_type,
            panic_mode=False,
            excluded_countries=excluded_countries or [],
            excluded_cities=excluded_cities or [],
            allowed_countries=allowed_countries or [],
            disable_lang_check=disable_lang_check,
            require_integrity=require_integrity,
            block_v2_gateway=block_v2_gateway,
            soft_pi_countries=soft_pi_countries or [],
            soft_pi_countries_any_asn=soft_pi_countries_any_asn or [],
            block_google_asn=block_google_asn,
            block_vpn_asn=block_vpn_asn,
            block_pi_unevaluated_combo=block_pi_unevaluated_combo,
            block_ipqs=block_ipqs,
            cloak_consumed_enabled=cloak_consumed_enabled,
            proxy_key=proxy_key,
            auth_token=auth_token,
            endpoint=endpoint,
            sdk_path=sdk_path or "/init",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.apps.append(app)
        self._save_apps()
        # Регистрируем proxy_key на кло (proxy_keys.json) — сразу live + на диск
        self.add_proxy_key(proxy_key, package_name, name)
        return app

    def update_app(self, app_id: str, updates: dict) -> AppEntry | None:
        for i, app in enumerate(self.apps):
            if app.id == app_id:
                data = app.model_dump()
                data.update({k: v for k, v in updates.items() if k != "id" and k != "created_at"})
                self.apps[i] = AppEntry(**data)
                self._save_apps()
                return self.apps[i]
        return None

    def delete_app(self, app_id: str) -> bool:
        app = self.get_app_by_id(app_id)
        before = len(self.apps)
        self.apps = [a for a in self.apps if a.id != app_id]
        if len(self.apps) < before:
            self._save_apps()
            if app:
                self.remove_proxy_key_for_package(app.package_name)
            return True
        return False


config_store = ConfigStore()
