import os
import json
import logging
from typing import Optional
from pathlib import Path

logger = logging.getLogger("play_integrity")

GCP_KEY_PATH = os.getenv("GCP_KEY_PATH", "config/gcp-key.json")
PACKAGE_NAME = os.getenv("PACKAGE_NAME", "")
CONFIG_DIR = Path(__file__).parent.parent / "config"


class IntegrityVerdict:
    def __init__(self, data):
        self.raw = data

        token_info = data.get("tokenPayloadExternal", {})

        req = token_info.get("requestDetails", {})
        self.package_name = req.get("requestPackageName", "")
        self.nonce = req.get("nonce", "")
        self.timestamp_millis = req.get("timestampMillis", "0")

        app = token_info.get("appIntegrity", {})
        self.app_recognition = app.get("appRecognitionVerdict", "UNEVALUATED")
        self.certificate_sha256 = app.get("certificateSha256Digest", [])
        self.version_code = app.get("versionCode", "")

        device = token_info.get("deviceIntegrity", {})
        self.device_recognition = device.get("deviceRecognitionVerdict", [])

        # 2026-06-22: PI v3 advanced — recentDeviceActivity (LEVEL_UNEVALUATED..LEVEL_4).
        # Real юзер активного телефона: LEVEL_1+. Scanner/fresh sandbox: UNEVALUATED.
        recent_activity = device.get("recentDeviceActivity", {})
        self.device_activity_level = recent_activity.get("deviceActivityLevel", "UNEVALUATED")

        account = token_info.get("accountDetails", {})
        self.app_licensing = account.get("appLicensingVerdict", "UNEVALUATED")

        # 2026-06-22: PI v3 advanced — environmentDetails (Play Protect + app access risk).
        # Real юзер активного Android: playProtectVerdict='NO_ISSUES'/'PLAY_PROTECT_OK'.
        # Scanner/fresh sandbox: 'UNEVALUATED' or 'NO_DATA'.
        # appsDetected с KNOWN_CAPTURING/CONTROLLING = reviewer пишет видео / Robo automation.
        env = token_info.get("environmentDetails", {})
        self.play_protect_verdict = env.get("playProtectVerdict", "")
        app_access_risk = env.get("appAccessRiskVerdict", {}) or {}
        self.apps_detected = app_access_risk.get("appsDetected", []) or []

    @property
    def meets_basic(self):
        return "MEETS_BASIC_INTEGRITY" in self.device_recognition

    @property
    def meets_device(self):
        return "MEETS_DEVICE_INTEGRITY" in self.device_recognition

    @property
    def meets_strong(self):
        return "MEETS_STRONG_INTEGRITY" in self.device_recognition

    @property
    def is_virtual_only(self):
        return (
            "MEETS_VIRTUAL_INTEGRITY" in self.device_recognition
            and "MEETS_DEVICE_INTEGRITY" not in self.device_recognition
            and "MEETS_STRONG_INTEGRITY" not in self.device_recognition
        )

    @property
    def is_empty_device(self):
        return len(self.device_recognition) == 0

    @property
    def is_recognized_app(self):
        return self.app_recognition == "PLAY_RECOGNIZED"

    @property
    def is_licensed(self):
        return self.app_licensing == "LICENSED"

    # 2026-06-22: PI v3 advanced verdict helpers.
    @property
    def is_activity_unevaluated(self) -> bool:
        """deviceActivityLevel=UNEVALUATED → Google не оценил активность (свежий девайс / scanner)."""
        return self.device_activity_level == "UNEVALUATED" or self.device_activity_level == "LEVEL_UNEVALUATED"

    @property
    def is_play_protect_unevaluated_or_nodata(self) -> bool:
        """playProtectVerdict UNEVALUATED/NO_DATA → Play Protect не успел оценить (scanner profile)."""
        return self.play_protect_verdict in ("UNEVALUATED", "NO_DATA", "")

    @property
    def has_capturing_app(self) -> bool:
        """appsDetected содержит CAPTURING (reviewer пишет видео для evidence)."""
        return any(
            "CAPTURING" in str(item).upper()
            for item in self.apps_detected
        )

    @property
    def has_controlling_app(self) -> bool:
        """appsDetected содержит CONTROLLING (Robo/UiAutomator automation framework)."""
        return any(
            "CONTROLLING" in str(item).upper()
            for item in self.apps_detected
        )


class PlayIntegrityClient:
    def __init__(self):
        self._services: dict[str, object] = {}
        self._default_service = None
        self._default_package = ""
        self._available = False

    def _load_all_keys(self) -> dict:
        """Перечитать все gcp-key*.json файлы. Возвращает map project_id -> service."""
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        services = {}
        for key_file in sorted(CONFIG_DIR.glob("gcp-key*.json")):
            try:
                with open(key_file) as f:
                    key_data = json.load(f)
                project_id = key_data.get("project_id", "")
                credentials = service_account.Credentials.from_service_account_file(
                    str(key_file),
                    scopes=["https://www.googleapis.com/auth/playintegrity"],
                )
                services[project_id] = build("playintegrity", "v1", credentials=credentials)
                logger.info(f"Play Integrity key loaded: {key_file.name} (project={project_id})")
            except Exception as e:
                logger.error(f"Failed to load {key_file.name}: {e}")
        return services

    def init(self):
        self._services = self._load_all_keys()
        if self._services:
            self._available = True

        key_path = Path(GCP_KEY_PATH)
        if key_path.exists():
            try:
                with open(key_path) as f:
                    default_project = json.load(f).get("project_id", "")
                self._default_service = self._services.get(default_project)
                self._default_package = PACKAGE_NAME
            except Exception:
                pass

        logger.info(f"Play Integrity: {len(self._services)} key(s) loaded, default_package={self._default_package}")

    def reload(self) -> list[str]:
        """Hot-reload всех gcp-key*.json без рестарта движка.
        Вызывается из /api/integrity/reload или после загрузки нового ключа через панель."""
        new_services = self._load_all_keys()
        self._services = new_services
        self._available = bool(new_services)

        # переподтянуть default_service
        key_path = Path(GCP_KEY_PATH)
        if key_path.exists():
            try:
                with open(key_path) as f:
                    default_project = json.load(f).get("project_id", "")
                self._default_service = self._services.get(default_project)
            except Exception:
                pass

        projects = sorted(self._services.keys())
        logger.info(f"Play Integrity reload: {len(projects)} key(s): {projects}")
        return projects

    def _get_service_for_package(self, package_name: str):
        from config import config_store

        app = config_store.get_app(package_name)
        if app and app.gcp_project_id and app.gcp_project_id in self._services:
            return self._services[app.gcp_project_id], package_name

        if self._default_service:
            return self._default_service, package_name or self._default_package

        if self._services:
            first_service = next(iter(self._services.values()))
            return first_service, package_name or self._default_package

        return None, package_name

    @property
    def available(self):
        return self._available

    async def verify_token(self, integrity_token: str, package_name: str = "") -> Optional[IntegrityVerdict]:
        if not self._available:
            logger.debug("Play Integrity not available, skipping verification")
            return None

        pkg = package_name or self._default_package
        if not pkg:
            logger.warning("No package name for integrity verification")
            return None

        service, resolved_pkg = self._get_service_for_package(pkg)
        if not service:
            logger.warning(f"No GCP service found for package {pkg}")
            return None

        try:
            import asyncio
            loop = asyncio.get_event_loop()

            def _decode():
                return service.v1().decodeIntegrityToken(
                    packageName=resolved_pkg,
                    body={"integrityToken": integrity_token},
                ).execute()

            result = await loop.run_in_executor(None, _decode)
            verdict = IntegrityVerdict(result)

            logger.info(
                f"Integrity [{resolved_pkg}]: app={verdict.app_recognition} "
                f"device={verdict.device_recognition} "
                f"license={verdict.app_licensing}"
            )
            return verdict

        except Exception as e:
            logger.error(f"Play Integrity verify failed [{resolved_pkg}]: {e}")
            return None


play_integrity_client = PlayIntegrityClient()
