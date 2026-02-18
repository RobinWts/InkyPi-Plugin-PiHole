from plugins.base_plugin.base_plugin import BasePlugin
from utils.app_utils import FONT_FAMILIES
import logging
import requests

logger = logging.getLogger(__name__)


class PiholeRateLimitError(RuntimeError):
    """Raised when Pi-hole API returns 429 or indicates rate limiting."""
    pass


class Pihole(BasePlugin):
    @classmethod
    def get_blueprint(cls):
        """Return the Flask blueprint for this plugin's API routes."""
        from . import api
        return api.pihole_bp

    def generate_settings_template(self):
        template_params = super().generate_settings_template()
        template_params["style_settings"] = True
        template_params["font_families"] = list(FONT_FAMILIES.keys())
        template_params["font_weights"] = ["normal", "bold"]
        return template_params

    def generate_image(self, settings, device_config):
        pihole_url = settings.get('piholeUrl', '').strip()
        if not pihole_url:
            raise RuntimeError("Pi-hole URL is required.")

        # Get SSL verification setting from plugin settings (not device config)
        allow_insecure_ssl = settings.get('allowInsecureSSL', 'false').lower() == 'true'

        try:
            # Fetch Pi-hole statistics
            stats_data = self.get_pihole_stats(pihole_url, device_config, allow_insecure_ssl)
        except PiholeRateLimitError:
            # Render dedicated "rate limit exceeded" view instead of raising
            dimensions = device_config.get_resolution()
            if device_config.get_config("orientation") == "vertical":
                dimensions = dimensions[::-1]
            plugin_settings = dict(settings)
            if not plugin_settings.get("backgroundColor"):
                plugin_settings["backgroundColor"] = "#ffffff"
            if not plugin_settings.get("textColor"):
                plugin_settings["textColor"] = "#000000"
            if not plugin_settings.get("backgroundOption"):
                plugin_settings["backgroundOption"] = "color"
            template_params = {"rate_limited": True, "plugin_settings": plugin_settings}
            image = self.render_image(dimensions, "pihole.html", "pihole.css", template_params)
            if not image:
                raise RuntimeError("Failed to render Pi-hole image, please check logs.")
            return image
        except Exception as e:
            logger.error(f"Failed to fetch Pi-hole data: {str(e)}")
            raise RuntimeError("Failed to fetch Pi-hole data. Please check your URL and Pi-hole authentication settings.")

        dimensions = device_config.get_resolution()
        if device_config.get_config("orientation") == "vertical":
            dimensions = dimensions[::-1]

        # Font settings from app_utils.FONT_FAMILIES
        font_family = settings.get("fontFamily", "Jost")
        font_weight = settings.get("fontWeight", "bold")

        # Display toggles and optional title
        custom_title = (settings.get("customTitle") or "").strip()
        show_title = settings.get("showTitle", "true").lower() == "true" and bool(custom_title)
        show_status = settings.get("showStatus", "true").lower() == "true"
        show_queries = settings.get("showQueries", "true").lower() == "true"
        show_queries_graph = settings.get("showQueriesGraph", "true").lower() == "true"
        show_clients = settings.get("showClients", "true").lower() == "true"
        show_blocklist = settings.get("showBlocklist", "true").lower() == "true"

        # Fallback: never render an empty page - if all content toggles are off, show all
        if not any((show_status, show_queries, show_clients, show_blocklist)):
            show_status = show_queries = show_clients = show_blocklist = True

        font_scale = {"x-small": 0.75, "small": 0.9, "normal": 1.0, "large": 1.15, "x-large": 1.3}.get(
            settings.get("fontSize", "normal"), 1.0
        )

        # Ensure style defaults for base template - prevents blank white when style section not saved
        plugin_settings = dict(settings)
        if not plugin_settings.get("backgroundColor"):
            plugin_settings["backgroundColor"] = "#ffffff"
        if not plugin_settings.get("textColor"):
            plugin_settings["textColor"] = "#000000"
        if not plugin_settings.get("backgroundOption"):
            plugin_settings["backgroundOption"] = "color"

        template_params = {
            "stats": stats_data,
            "plugin_settings": plugin_settings,
            "show_title": show_title,
            "custom_title": custom_title,
            "show_status": show_status,
            "show_queries": show_queries,
            "show_queries_graph": show_queries_graph,
            "show_clients": show_clients,
            "show_blocklist": show_blocklist,
            "font_family": font_family,
            "font_weight": font_weight,
            "font_scale": font_scale,
        }

        image = self.render_image(dimensions, "pihole.html", "pihole.css", template_params)

        if not image:
            raise RuntimeError("Failed to render Pi-hole image, please check logs.")

        return image

    def get_pihole_stats(self, pihole_url: str, device_config, allow_insecure_ssl: bool) -> dict:
        """Fetch statistics from Pi-hole API.

        Requires Pi-hole v6+ with REST API at /api/*.
        Uses session-based authentication if password is set, otherwise accesses endpoints without auth.
        Raises PiholeRateLimitError when API returns 429 (rate limit).
        """
        base_url = pihole_url.rstrip("/")
        try:
            stats = self._get_stats(base_url, device_config, allow_insecure_ssl)
        except PiholeRateLimitError:
            raise
        if stats is not None:
            return stats

        raise RuntimeError("Failed to fetch Pi-hole stats. Ensure you're using Pi-hole v6+ and check your URL and authentication settings.")

    def _get_stats(self, base_url: str, device_config, allow_insecure_ssl: bool) -> dict | None:
        """Fetch statistics from Pi-hole v6+ REST API."""
        url = f"{base_url}/api/stats/summary"
        headers = {}
        try:
            resp = requests.get(url, timeout=10, verify=not allow_insecure_ssl, headers=headers)
            if resp.status_code == 429 or self._response_indicates_rate_limit(resp):
                raise PiholeRateLimitError("Pi-hole API rate limit exceeded.")
            if resp.status_code == 401:
                # If the API requires auth, try to login if PIHOLE_PASSWORD is configured.
                password = (device_config.load_env_key("PIHOLE_PASSWORD") or "").strip()
                if not password:
                    logger.warning("Pi-hole API requires authentication but PIHOLE_PASSWORD is not configured")
                    return None

                sid = self._authenticate_sid(base_url, password, allow_insecure_ssl)
                headers["X-FTL-SID"] = sid
                resp = requests.get(url, headers=headers, timeout=10, verify=not allow_insecure_ssl)

            if resp.status_code == 429 or self._response_indicates_rate_limit(resp):
                raise PiholeRateLimitError("Pi-hole API rate limit exceeded.")
            if not 200 <= resp.status_code < 300:
                logger.warning(f"Pi-hole API returned status {resp.status_code}")
                return None

            data = resp.json()
            
            # Fetch blocking status separately if not in summary (some API versions don't include it)
            if "blocking" not in data and "status" not in data:
                blocking_status = self._get_blocking_status(base_url, headers, allow_insecure_ssl)
                if blocking_status is not None:
                    data["blocking"] = blocking_status
            
            return self._normalize_stats(data)
        except PiholeRateLimitError:
            raise
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL error connecting to Pi-hole: {e}. Try enabling 'Allow insecure HTTPS' if using a self-signed certificate.")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect to Pi-hole API: {e}")
            return None
        except Exception as e:
            logger.error(f"Pi-hole API request failed: {e}")
            return None

    def _get_blocking_status(self, base_url: str, headers: dict, allow_insecure_ssl: bool) -> bool | None:
        """Fetch DNS blocking status from /api/dns/blocking endpoint."""
        url = f"{base_url}/api/dns/blocking"
        try:
            resp = requests.get(url, timeout=5, verify=not allow_insecure_ssl, headers=headers)
            if resp.status_code == 200:
                blocking_data = resp.json()
                return blocking_data.get("blocking")
        except Exception as e:
            logger.debug(f"Could not fetch blocking status: {e}")
        return None

    def _response_indicates_rate_limit(self, resp: requests.Response) -> bool:
        """True if response body suggests rate limiting (e.g. 401/403 with rate-limit message)."""
        if resp.status_code != 401 and resp.status_code != 403:
            return False
        text = (resp.text or "").lower()
        return "rate limit" in text or "too many requests" in text or "throttl" in text

    def _authenticate_sid(self, base_url: str, password: str, allow_insecure_ssl: bool) -> str:
        auth_url = f"{base_url}/api/auth"
        try:
            resp = requests.post(auth_url, json={"password": password}, timeout=10, verify=not allow_insecure_ssl)
            if resp.status_code == 429 or self._response_indicates_rate_limit(resp):
                raise PiholeRateLimitError("Pi-hole API rate limit exceeded.")
            if not 200 <= resp.status_code < 300:
                raise RuntimeError("Authentication failed.")
            data = resp.json()
            sid = (((data or {}).get("session") or {}).get("sid") or "").strip()
            if not sid:
                raise RuntimeError("Authentication did not return a session id.")
            return sid
        except PiholeRateLimitError:
            raise
        except Exception as e:
            logger.error(f"Pi-hole authentication failed: {e}")
            raise RuntimeError("Pi-hole authentication failed. Check PIHOLE_PASSWORD or configure an application password.")

    def _normalize_stats(self, data: dict) -> dict:
        """Normalize Pi-hole v6+ API stats into a common shape for the template."""
        if not isinstance(data, dict):
            return {}

        # If the API already returns data in the expected format, normalize status and active_clients
        if all(k in data for k in ("dns_queries_today", "ads_blocked_today", "ads_percentage_today")):
            out = dict(data)
            # Normalize status field - API may return "blocking" as boolean
            if "status" not in out or out.get("status") is None:
                blocking = data.get("blocking")
                if isinstance(blocking, bool):
                    out["status"] = "enabled" if blocking else "disabled"
                elif blocking is not None:
                    out["status"] = str(blocking).lower()
                else:
                    out["status"] = "enabled"  # Default assumption
            # Normalize status to string if it's a boolean
            elif isinstance(out.get("status"), bool):
                out["status"] = "enabled" if out["status"] else "disabled"
            if "active_clients" not in out:
                out["active_clients"] = (
                    (data.get("clients") or {}).get("active")
                    or (data.get("clients") or {}).get("count")
                    or data.get("unique_clients")
                    or 0
                )
            return out

        # Map modern API response fields to expected template format.
        # Field names may differ between Pi-hole v6 versions; keep this defensive.
        queries_total = (
            (data.get("queries") or {}).get("total")
            or (data.get("dns") or {}).get("queries")
            or data.get("dns_queries_today")
            or 0
        )
        blocked_total = (
            (data.get("queries") or {}).get("blocked")
            or (data.get("blocked") or {}).get("queries")
            or data.get("ads_blocked_today")
            or 0
        )

        try:
            pct_blocked = float(
                (data.get("queries") or {}).get("percent_blocked")
                or (data.get("blocked") or {}).get("percent")
                or data.get("ads_percentage_today")
                or 0
            )
        except Exception:
            pct_blocked = 0.0

        domains_blocked = (
            (data.get("gravity") or {}).get("domains_being_blocked")
            or (data.get("domains") or {}).get("blocked")
            or data.get("domains_being_blocked")
            or 0
        )

        # Status field - API returns "blocking" as boolean (true=enabled, false=disabled)
        blocking = data.get("blocking")
        status = data.get("status")
        
        if status is None and blocking is not None:
            # Use blocking field if status is missing
            if isinstance(blocking, bool):
                status = "enabled" if blocking else "disabled"
            else:
                status = str(blocking).lower()
        elif status is not None:
            # Normalize existing status field
            if isinstance(status, bool):
                status = "enabled" if status else "disabled"
            else:
                status = str(status).lower()
        else:
            # Fallback: check enabled field or default to enabled
            enabled = data.get("enabled")
            if isinstance(enabled, bool):
                status = "enabled" if enabled else "disabled"
            else:
                status = "enabled"  # Default assumption

        # Active/unique clients - field name varies across Pi-hole API versions
        active_clients = (
            (data.get("clients") or {}).get("active")
            or (data.get("clients") or {}).get("count")
            or data.get("unique_clients")
            or data.get("active_clients")
            or 0
        )

        return {
            "status": status,
            "dns_queries_today": queries_total,
            "ads_blocked_today": blocked_total,
            "ads_percentage_today": pct_blocked,
            "domains_being_blocked": domains_blocked,
            "active_clients": active_clients,
            "queries_forwarded": (data.get("queries") or {}).get("forwarded") or data.get("queries_forwarded") or 0,
            "queries_cached": (data.get("queries") or {}).get("cached") or data.get("queries_cached") or 0,
        }
