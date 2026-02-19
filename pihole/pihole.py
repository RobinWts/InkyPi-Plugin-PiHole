from plugins.base_plugin.base_plugin import BasePlugin
from utils.app_utils import FONT_FAMILIES
import logging
import re
import time
import requests

logger = logging.getLogger(__name__)

# Pattern for Pi-hole internal client IDs (e.g. p200300e60f06c400251d5...)
_INTERNAL_ID_PATTERN = re.compile(r"^p[0-9a-f]{12,}$", re.IGNORECASE)


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
        show_queries_forwarded = settings.get("showQueriesForwarded", "true").lower() == "true"
        show_clients_blocklist_raw = settings.get("showClientsBlocklist", "").lower()
        if show_clients_blocklist_raw == "":
            show_clients_blocklist = (
                settings.get("showClients", "true").lower() == "true"
                or settings.get("showBlocklist", "true").lower() == "true"
            )
        else:
            show_clients_blocklist = show_clients_blocklist_raw == "true"
        show_top_clients = settings.get("showTopClients", "true").lower() == "true"
        show_history_chart = settings.get("showHistoryChart", "true").lower() == "true"

        # Fallback: never render an empty page - if all content toggles are off, show all
        if not any((show_status, show_queries, show_queries_graph, show_queries_forwarded, show_clients_blocklist, show_top_clients, show_history_chart)):
            show_status = show_queries = show_queries_graph = show_queries_forwarded = show_clients_blocklist = show_top_clients = show_history_chart = True

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

        # Fetch top clients if enabled (separate API call, may fail)
        top_clients = None
        if show_top_clients:
            top_clients = self._get_top_clients(
                settings.get("piholeUrl", "").rstrip("/"),
                device_config,
                settings.get("allowInsecureSSL", "false").lower() == "true",
                limit=5,
            )

        # Fetch 24h history for chart if enabled (separate API call, may fail)
        history_hours = None
        chart_max = 1
        if show_history_chart:
            history_hours = self._get_history_24h(
                settings.get("piholeUrl", "").rstrip("/"),
                device_config,
                settings.get("allowInsecureSSL", "false").lower() == "true",
            )
            if history_hours:
                chart_max = max(1, max(h.get("total", 0) for h in history_hours))

        template_params = {
            "stats": stats_data,
            "plugin_settings": plugin_settings,
            "show_title": show_title,
            "custom_title": custom_title,
            "show_status": show_status,
            "show_queries": show_queries,
            "show_queries_graph": show_queries_graph,
            "show_queries_forwarded": show_queries_forwarded,
            "show_clients_blocklist": show_clients_blocklist,
            "show_top_clients": show_top_clients,
            "top_clients": top_clients,
            "show_history_chart": show_history_chart,
            "history_hours": history_hours,
            "chart_max": chart_max,
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

    def _get_history_24h(
        self, base_url: str, device_config, allow_insecure_ssl: bool
    ) -> list[dict] | None:
        """Fetch last 24h hourly query history from Pi-hole /api/history. Returns None on failure."""
        if not base_url:
            logger.debug("[history] No base_url, skipping")
            return None
        url = f"{base_url}/api/history"
        headers: dict[str, str] = {}
        try:
            resp = requests.get(url, timeout=10, verify=not allow_insecure_ssl, headers=headers)
            if resp.status_code == 401:
                password = (device_config.load_env_key("PIHOLE_PASSWORD") or "").strip()
                if not password:
                    logger.debug("[history] 401 but no PIHOLE_PASSWORD, skipping")
                    return None
                sid = self._authenticate_sid(base_url, password, allow_insecure_ssl)
                headers["X-FTL-SID"] = sid
                resp = requests.get(url, headers=headers, timeout=10, verify=not allow_insecure_ssl)
            if not 200 <= resp.status_code < 300:
                logger.debug("[history] API returned status %s", resp.status_code)
                return None
            data = resp.json()
            logger.debug("[history] API OK, top-level keys: %s", list(data.keys()) if isinstance(data, dict) else type(data))
        except Exception as e:
            logger.debug("[history] Request failed: %s", e)
            return None

        raw = data.get("history") if isinstance(data, dict) else (data if isinstance(data, list) else None)
        if not raw:
            logger.debug("[history] No 'history' array in response (keys: %s)", list(data.keys()) if isinstance(data, dict) else "N/A")
            return None
        if not isinstance(raw, list):
            logger.debug("[history] 'history' is not a list: %s", type(raw))
            return None

        first_item = raw[0] if raw else None
        first_keys = list(first_item.keys()) if isinstance(first_item, dict) else "N/A"
        logger.debug("[history] Raw history length: %d, first item keys: %s", len(raw), first_keys)
        if isinstance(first_item, dict) and first_item:
            logger.debug("[history] First item sample: %s", {k: first_item.get(k) for k in list(first_item.keys())[:8]})

        now_ts = int(time.time())
        buckets: list[dict] = [
            {"hour": i, "total": 0, "blocked": 0, "allowed": 0}
            for i in range(24)
        ]

        items_in_window = 0
        items_skipped = {"not_dict": 0, "no_ts": 0, "ts_out_of_range": 0}
        for item in raw:
            if not isinstance(item, dict):
                items_skipped["not_dict"] += 1
                continue
            ts = item.get("timestamp") or item.get("time") or 0
            try:
                ts = int(ts)
            except (ValueError, TypeError):
                items_skipped["no_ts"] += 1
                continue
            if ts < now_ts - 86400 or ts > now_ts:
                items_skipped["ts_out_of_range"] += 1
                continue
            items_in_window += 1
            total_val = int(item.get("total") or item.get("queries") or 0)
            blocked_val = int(item.get("blocked") or 0)
            forwarded = int(item.get("forwarded") or item.get("forwarded_queries") or 0)
            cached = int(item.get("cached") or item.get("cached_queries") or 0)
            permitted = int(item.get("permitted") or item.get("permitted_queries") or 0)
            if blocked_val == 0 and (forwarded or cached or permitted):
                allowed = forwarded + cached + permitted
                blocked_val = max(0, total_val - allowed)
            else:
                allowed = max(0, total_val - blocked_val)
            offset_hours = (now_ts - ts) / 3600
            bucket_idx = max(0, min(23, 23 - int(offset_hours)))
            if 0 <= bucket_idx < 24:
                buckets[bucket_idx]["total"] += total_val
                buckets[bucket_idx]["blocked"] += blocked_val
                buckets[bucket_idx]["allowed"] += allowed

        logger.debug("[history] Items in 24h window: %d, skipped: %s", items_in_window, items_skipped)
        bucket_totals = [b["total"] for b in buckets]
        chart_max = max(bucket_totals) if bucket_totals else 0
        logger.debug("[history] Bucket totals (24h): %s, max=%s", bucket_totals, chart_max)
        if items_in_window > 0 and chart_max == 0:
            logger.debug("[history] WARNING: items in window but all bucket totals are 0 (field names may differ)")

        return buckets

    def _looks_like_internal_id(self, s: str) -> bool:
        """True if string looks like Pi-hole internal client ID (e.g. p200300e60f06c400251d5...)."""
        if not s or not isinstance(s, str):
            return False
        s = s.strip()
        return bool(_INTERNAL_ID_PATTERN.match(s))

    def _get_clients_lookup(
        self, base_url: str, headers: dict[str, str], allow_insecure_ssl: bool
    ) -> dict[str, str]:
        """Fetch /api/clients and build id/identifier -> readable name map for display."""
        url = f"{base_url}/api/clients"
        lookup: dict[str, str] = {}
        try:
            resp = requests.get(url, timeout=5, verify=not allow_insecure_ssl, headers=headers)
            if resp.status_code != 200:
                return lookup
            data = resp.json()
        except Exception as e:
            logger.debug(f"Could not fetch clients for lookup: {e}")
            return lookup

        # API may return {"clients": [...]} or array; each item may have id, client, comment
        raw = data if isinstance(data, list) else (data.get("clients") or [])
        if not isinstance(raw, list):
            return lookup

        for c in raw:
            if not isinstance(c, dict):
                continue
            uid = c.get("id") or c.get("client") or c.get("ip")
            if uid:
                uid = str(uid).strip()
            display = (
                (c.get("comment") or "").strip()
                or (c.get("hostname") or "").strip()
                or (c.get("description") or "").strip()
            )
            if uid and display:
                lookup[uid] = display
            elif uid:
                # Use the identifier itself if it looks readable (IP, hostname)
                if not self._looks_like_internal_id(uid):
                    lookup[uid] = uid
        return lookup

    def _get_top_clients(
        self, base_url: str, device_config, allow_insecure_ssl: bool, limit: int = 5
    ) -> list[dict] | None:
        """Fetch top clients from Pi-hole v6+ API. Returns None on any failure (not available)."""
        if not base_url:
            return None
        url = f"{base_url}/api/stats/top_clients"
        headers: dict[str, str] = {}
        try:
            resp = requests.get(url, timeout=5, verify=not allow_insecure_ssl, headers=headers)
            if resp.status_code == 401:
                password = (device_config.load_env_key("PIHOLE_PASSWORD") or "").strip()
                if not password:
                    return None
                sid = self._authenticate_sid(base_url, password, allow_insecure_ssl)
                headers["X-FTL-SID"] = sid
                resp = requests.get(url, headers=headers, timeout=5, verify=not allow_insecure_ssl)
            if not 200 <= resp.status_code < 300:
                return None
            data = resp.json()
        except Exception as e:
            logger.debug(f"Could not fetch top clients: {e}")
            return None

        # Parse flexibly: {"top_clients": [...]}, {"clients": [...]}, or array
        if isinstance(data, list):
            raw = data
        else:
            raw = data.get("top_clients") or data.get("clients")
        if not raw or not isinstance(raw, list):
            return None

        # Try to get client names from /api/clients for internal-ID resolution
        clients_lookup = self._get_clients_lookup(base_url, headers, allow_insecure_ssl)

        result: list[dict] = []
        for idx, item in enumerate(raw[: limit * 2]):
            if len(result) >= limit:
                break
            if isinstance(item, dict):
                # Prefer human-readable fields; avoid internal IDs when possible
                hostname = (item.get("hostname") or "").strip()
                ip = (item.get("ip") or "").strip()
                comment = (item.get("comment") or "").strip()
                description = (item.get("description") or "").strip()
                name = (item.get("name") or item.get("client") or item.get("id") or "").strip()
                count_val = item.get("count") or item.get("queries") or 0

                display = hostname or comment or description or ip or name
                if display and self._looks_like_internal_id(display):
                    # Resolve internal ID via clients lookup, or fallback to rank label
                    candidate_id = name or item.get("id") or display
                    display = (
                        clients_lookup.get(display)
                        or (clients_lookup.get(candidate_id) if candidate_id else None)
                        or f"Client #{len(result) + 1}"
                    )
                if display and str(display).strip():
                    result.append({"name": str(display).strip(), "count": int(count_val)})
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                label = str(item[0]).strip()
                if label and self._looks_like_internal_id(label):
                    label = clients_lookup.get(label) or f"Client #{idx + 1}"
                result.append({"name": label or f"Client #{idx + 1}", "count": int(item[1] or 0)})
        return result if result else None

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
            if "queries_forwarded" not in out:
                out["queries_forwarded"] = (data.get("queries") or {}).get("forwarded") or data.get("queries_forwarded") or 0
            if "queries_cached" not in out:
                out["queries_cached"] = (data.get("queries") or {}).get("cached") or data.get("queries_cached") or 0
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
