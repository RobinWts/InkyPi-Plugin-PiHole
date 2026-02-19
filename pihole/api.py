"""API and action registration for pihole plugin."""

import logging
import requests

from flask import Blueprint

from . import pihole as plugin_module

logger = logging.getLogger(__name__)

pihole_bp = Blueprint("pihole_api", __name__)


@pihole_bp.record_once
def _register_actions(state):
    """Register 1 anytime action and 6 display actions with hardwarebuttons."""
    try:
        from plugins.hardwarebuttons import action_registry
    except ImportError:
        logger.debug("hardwarebuttons plugin not installed, skipping action registration")
        return

    def _find_pihole_instance(refs):
        """Find a pihole plugin instance in any playlist."""
        device_config = refs.get("device_config")
        playlist_manager = device_config.get_playlist_manager()

        # Try active playlist first
        active_name = playlist_manager.active_playlist
        if active_name:
            playlist = playlist_manager.get_playlist(active_name)
            if playlist:
                instance = playlist.find_plugin("pihole", None)
                if instance:
                    return playlist, instance

        # Search all playlists
        for name in playlist_manager.get_playlist_names():
            pl = playlist_manager.get_playlist(name)
            if pl:
                for pi in pl.plugins:
                    if pi.plugin_id == "pihole":
                        return pl, pi

        return None, None

    def _force_refresh(refs, playlist, instance):
        """Force refresh of a plugin instance."""
        refresh_task = refs.get("refresh_task")
        if playlist and instance:
            from refresh_task import PlaylistRefresh
            refresh_task.manual_update(PlaylistRefresh(playlist, instance, force=True))
        elif instance:
            from refresh_task import ManualRefresh
            refresh_task.manual_update(ManualRefresh("pihole", instance.settings))

    def _find_playlist_for_instance(refs, instance):
        """Find the playlist containing a given plugin instance."""
        device_config = refs.get("device_config")
        playlist_manager = device_config.get_playlist_manager()

        for name in playlist_manager.get_playlist_names():
            pl = playlist_manager.get_playlist(name)
            if pl:
                for pi in pl.plugins:
                    if pi.plugin_id == instance.plugin_id and pi.name == instance.name:
                        return pl
        return None

    def _get_displayed_pihole_instance(refs):
        """Resolve the Pi-hole instance that is currently displayed (for display actions).

        Uses refresh_info so we use the same instance that is on screen, not a random one.
        Falls back to current_plugin_instance from refs, then to refresh_info lookup.
        """
        device_config = refs.get("device_config")
        if not device_config:
            return None, None

        # Prefer instance already resolved by action_registry
        current_instance = refs.get("current_plugin_instance")
        if current_instance and getattr(current_instance, "plugin_id", None) == "pihole":
            playlist = _find_playlist_for_instance(refs, current_instance)
            return playlist, current_instance

        # Resolve from refresh_info: this is the instance that is actually displayed
        refresh_info = device_config.get_refresh_info()
        if not refresh_info:
            return None, None

        plugin_id = getattr(refresh_info, "plugin_id", None)
        if plugin_id != "pihole":
            return None, None

        playlist_name = getattr(refresh_info, "playlist", None)
        instance_name = getattr(refresh_info, "plugin_instance", None)

        if playlist_name and instance_name and getattr(refresh_info, "refresh_type", None) == "Playlist":
            playlist_manager = device_config.get_playlist_manager()
            playlist = playlist_manager.get_playlist(playlist_name)
            if playlist:
                instance = playlist.find_plugin("pihole", instance_name)
                if instance:
                    return playlist, instance

        # Manual Update or missing playlist context: use active playlist's pihole instance
        playlist_manager = device_config.get_playlist_manager()
        active_name = playlist_manager.active_playlist
        if active_name:
            playlist = playlist_manager.get_playlist(active_name)
            if playlist:
                for pi in playlist.plugins:
                    if pi.plugin_id == "pihole":
                        return playlist, pi

        # Last resort: any pihole instance in any playlist
        for name in playlist_manager.get_playlist_names():
            pl = playlist_manager.get_playlist(name)
            if pl:
                for pi in pl.plugins:
                    if pi.plugin_id == "pihole":
                        return pl, pi

        return None, None

    def anytime_show_pihole(refs):
        """Anytime action: force display of pihole plugin.
        
        Prefers the currently displayed pihole instance if one exists, otherwise
        finds any pihole instance. Gracefully does nothing if no instance exists.
        """
        # First try to use the currently displayed instance (if pihole is on screen)
        playlist, instance = _get_displayed_pihole_instance(refs)
        
        # If nothing is displayed or it's not pihole, find any pihole instance
        if not instance:
            playlist, instance = _find_pihole_instance(refs)
        
        # If we found an instance, force refresh it
        if playlist and instance:
            _force_refresh(refs, playlist, instance)
            logger.info("pihole: anytime action 'show Pihole' triggered for instance '%s'", instance.name)
        else:
            # No pihole instance exists - gracefully do nothing
            logger.debug("pihole: anytime action 'show Pihole' - no pihole instance found, doing nothing")

    def _set_blocking(refs, blocking, timer_seconds=None):
        """Set Pi-hole blocking status via API. Uses the instance that is currently displayed."""
        _playlist, current_instance = _get_displayed_pihole_instance(refs)
        if not current_instance:
            logger.warning("pihole: no displayed pihole instance for blocking action")
            return False

        settings = current_instance.settings
        pihole_url = settings.get("piholeUrl", "").strip()
        if not pihole_url:
            logger.error("pihole: piholeUrl not configured")
            return False

        allow_insecure_ssl = settings.get("allowInsecureSSL", "false").lower() == "true"
        device_config = refs.get("device_config")

        try:
            # Get plugin config to create plugin instance for helper methods
            plugin_config = device_config.get_plugin("pihole")
            if not plugin_config:
                logger.error("pihole: plugin config not found")
                return False
            pihole_instance = plugin_module.Pihole(plugin_config)

            # Authenticate if needed
            password = (device_config.load_env_key("PIHOLE_PASSWORD") or "").strip()
            headers = {}
            if password:
                sid = pihole_instance._authenticate_sid(
                    pihole_url.rstrip("/"), password, allow_insecure_ssl
                )
                headers["X-FTL-SID"] = sid

            # Set blocking status
            base_url = pihole_url.rstrip("/")
            url = f"{base_url}/api/dns/blocking"
            payload = {"blocking": blocking}
            if timer_seconds is not None:
                payload["timer"] = timer_seconds

            resp = requests.post(
                url, json=payload, timeout=10, verify=not allow_insecure_ssl, headers=headers
            )

            if resp.status_code == 429 or pihole_instance._response_indicates_rate_limit(resp):
                logger.warning("pihole: rate limit when setting blocking status")
                return False

            if not 200 <= resp.status_code < 300:
                logger.error(f"pihole: failed to set blocking status: {resp.status_code}")
                return False

            logger.info(f"pihole: blocking set to {blocking}, timer={timer_seconds}")
            return True

        except Exception as e:
            logger.error(f"pihole: error setting blocking status: {e}")
            return False

    def _get_blocking_status(refs):
        """Get current blocking status from Pi-hole API. Uses the instance that is currently displayed."""
        _playlist, current_instance = _get_displayed_pihole_instance(refs)
        if not current_instance:
            return None

        settings = current_instance.settings
        pihole_url = settings.get("piholeUrl", "").strip()
        if not pihole_url:
            return None

        allow_insecure_ssl = settings.get("allowInsecureSSL", "false").lower() == "true"
        device_config = refs.get("device_config")

        try:
            # Get plugin config to create plugin instance for helper methods
            plugin_config = device_config.get_plugin("pihole")
            if not plugin_config:
                return None
            pihole_instance = plugin_module.Pihole(plugin_config)
            password = (device_config.load_env_key("PIHOLE_PASSWORD") or "").strip()
            headers = {}
            if password:
                sid = pihole_instance._authenticate_sid(
                    pihole_url.rstrip("/"), password, allow_insecure_ssl
                )
                headers["X-FTL-SID"] = sid

            base_url = pihole_url.rstrip("/")
            blocking_status = pihole_instance._get_blocking_status(
                base_url, headers, allow_insecure_ssl
            )
            return blocking_status
        except Exception as e:
            logger.error(f"pihole: error getting blocking status: {e}")
            return None

    # Action implementations (action_type string -> callback)
    def _do_toggle(refs):
        playlist, current_instance = _get_displayed_pihole_instance(refs)
        if not current_instance:
            return
        current_status = _get_blocking_status(refs)
        if current_status is None:
            logger.warning("pihole: could not determine current blocking status")
            return
        if _set_blocking(refs, not current_status):
            _force_refresh(refs, playlist, current_instance)

    def _do_blocking_off(refs):
        playlist, current_instance = _get_displayed_pihole_instance(refs)
        if not current_instance:
            return
        if _set_blocking(refs, False):
            _force_refresh(refs, playlist, current_instance)

    def _do_blocking_on(refs):
        playlist, current_instance = _get_displayed_pihole_instance(refs)
        if not current_instance:
            return
        if _set_blocking(refs, True):
            _force_refresh(refs, playlist, current_instance)

    def _do_blocking_off_5min(refs):
        playlist, current_instance = _get_displayed_pihole_instance(refs)
        if not current_instance:
            return
        if _set_blocking(refs, False, timer_seconds=300):
            _force_refresh(refs, playlist, current_instance)

    def _do_blocking_off_30min(refs):
        playlist, current_instance = _get_displayed_pihole_instance(refs)
        if not current_instance:
            return
        if _set_blocking(refs, False, timer_seconds=1800):
            _force_refresh(refs, playlist, current_instance)

    def _do_blocking_off_1hour(refs):
        playlist, current_instance = _get_displayed_pihole_instance(refs)
        if not current_instance:
            return
        if _set_blocking(refs, False, timer_seconds=3600):
            _force_refresh(refs, playlist, current_instance)

    ACTION_IMPL = {
        "toggle": _do_toggle,
        "off": _do_blocking_off,
        "on": _do_blocking_on,
        "off_5m": _do_blocking_off_5min,
        "off_30m": _do_blocking_off_30min,
        "off_1h": _do_blocking_off_1hour,
    }
    DEFAULT_SLOT_MAPPING = ["toggle", "off", "on", "off_5m", "off_30m", "off_1h"]

    def make_display_slot_handler(slot_index):
        """Return a callback that dispatches to the action mapped for this slot in instance settings."""
        def handler(refs):
            playlist, current_instance = _get_displayed_pihole_instance(refs)
            if not current_instance:
                return
            settings = current_instance.settings
            key = f"displayAction{slot_index + 1}"
            action_type = settings.get(key, DEFAULT_SLOT_MAPPING[slot_index])
            impl = ACTION_IMPL.get(action_type)
            if impl:
                impl(refs)
            else:
                logger.warning("pihole: unknown displayAction%d value '%s', using default", slot_index + 1, action_type)
                ACTION_IMPL.get(DEFAULT_SLOT_MAPPING[slot_index])(refs)
        return handler

    action_registry.register_actions(
        plugin_id="pihole",
        anytime_actions={
            "show_pihole": {
                "label": "Show Pihole",
                "callback": anytime_show_pihole,
            }
        },
        display_actions=[make_display_slot_handler(i) for i in range(6)],
    )
    logger.info("pihole: registered 1 anytime + 6 display actions (configurable mapping)")
