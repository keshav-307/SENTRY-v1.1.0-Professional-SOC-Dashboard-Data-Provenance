import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_FEED_PATH = (
    Path(__file__).resolve().parent.parent
    / "config"
    / "threat_feed.json"
)


class AbuseIPDBProvider:
    """
    Optional AbuseIPDB IP reputation provider.

    The API key is read from the ABUSEIPDB_API_KEY environment variable
    only. No key is ever stored in the project or written to logs.
    """

    name = "abuseipdb"

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key=None, timeout=5):
        self.api_key = api_key or os.environ.get(
            "ABUSEIPDB_API_KEY",
            "",
        )
        self.timeout = timeout

    @property
    def available(self):
        return bool(self.api_key)

    def lookup(self, ip_address):
        if not self.available:
            raise RuntimeError(
                "ABUSEIPDB_API_KEY is not configured."
            )

        query = urllib.parse.urlencode(
            {
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
            }
        )

        request = urllib.request.Request(
            f"{self.API_URL}?{query}",
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
            },
        )

        with urllib.request.urlopen(
            request,
            timeout=self.timeout,
        ) as response:
            payload = json.loads(
                response.read().decode("utf-8")
            )

        data = payload.get("data", {})

        score = data.get("abuseConfidenceScore")

        if not isinstance(score, (int, float)):
            score = None

        if score is not None and score >= 75:
            status = "malicious"
        elif score is not None and score >= 25:
            status = "suspicious"
        else:
            status = "unknown"

        return {
            "status": status,
            "score": score,
            "country": data.get("countryCode"),
            "total_reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt"),
        }


class ThreatIntel:
    """
    Enrichment for IP addresses.

    Sources:
      * local threat feed (config/threat_feed.json)
      * optional AbuseIPDB provider when ABUSEIPDB_API_KEY is set
      * SQLite cache to avoid repeated lookups

    Rules:
      * private, loopback, link-local, multicast and reserved addresses
        are reported as private/reserved and are never marked malicious
      * an indicator with no supporting data is reported as unknown
      * no indicator is ever labelled malicious without evidence
    """

    def __init__(
        self,
        database=None,
        feed_path=None,
        provider=None,
        cache_ttl_seconds=86400,
    ):
        self.database = database
        self.feed_path = Path(feed_path) if feed_path else DEFAULT_FEED_PATH
        self.provider = provider
        self.cache_ttl_seconds = cache_ttl_seconds
        self.feed = self._load_feed()

    def _load_feed(self):
        feed = {
            "malicious_ips": [],
            "suspicious_ips": [],
        }

        try:
            loaded = json.loads(
                self.feed_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            return feed

        if not isinstance(loaded, dict):
            return feed

        for key in feed:
            values = loaded.get(key, [])
            if isinstance(values, list):
                feed[key] = [
                    str(value).strip()
                    for value in values
                    if str(value).strip()
                ]

        return feed

    # ---------------------------------------------------------
    # CLASSIFICATION HELPERS
    # ---------------------------------------------------------

    @staticmethod
    def classify_address(ip_address):
        """
        Return (status, detail) for addresses that must never be
        looked up externally.
        """

        try:
            address = ipaddress.ip_address(ip_address)
        except ValueError:
            return "invalid", "Not a valid IP address."

        if address.is_loopback:
            return "private", "Loopback address."

        if address.is_private:
            return "private", "Private or reserved address."

        if address.is_link_local:
            return "private", "Link-local address."

        if address.is_multicast:
            return "reserved", "Multicast address."

        if address.is_reserved or address.is_unspecified:
            return "reserved", "Reserved address."

        return None, None

    # ---------------------------------------------------------
    # CACHE
    # ---------------------------------------------------------

    def _cache_get(self, ip_address):
        if self.database is None:
            return None

        try:
            return self.database.get_intel_cache(ip_address)
        except Exception:
            return None

    def _cache_set(self, entry):
        if self.database is None:
            return

        try:
            self.database.set_intel_cache(entry)
        except Exception:
            pass

    @staticmethod
    def _cache_is_fresh(entry, ttl_seconds):
        if not entry:
            return False

        last_checked = entry.get("last_checked")

        if not last_checked:
            return False

        try:
            checked = datetime.fromisoformat(str(last_checked))
        except ValueError:
            return False

        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)

        age = (
            datetime.now(timezone.utc) - checked
        ).total_seconds()

        return 0 <= age <= ttl_seconds

    # ---------------------------------------------------------
    # PUBLIC API
    # ---------------------------------------------------------

    def enrich_ip(self, ip_address):
        checked_at = datetime.now(timezone.utc).isoformat()

        if not ip_address:
            return {
                "ip": None,
                "status": "unknown",
                "source": None,
                "score": None,
                "details": "No source IP recorded.",
                "last_checked": checked_at,
            }

        status, detail = self.classify_address(ip_address)

        if status is not None:
            return {
                "ip": ip_address,
                "status": status,
                "source": "classification",
                "score": None,
                "details": detail,
                "last_checked": checked_at,
            }

        cached = self._cache_get(ip_address)

        if self._cache_is_fresh(
            cached,
            self.cache_ttl_seconds,
        ):
            return cached

        if ip_address in self.feed["malicious_ips"]:
            entry = self._entry(
                ip_address,
                status="malicious",
                source="local_feed",
                score=1.0,
                details="Listed in the local threat feed as malicious.",
                checked_at=checked_at,
            )
            self._cache_set(entry)
            return entry

        if ip_address in self.feed["suspicious_ips"]:
            entry = self._entry(
                ip_address,
                status="suspicious",
                source="local_feed",
                score=0.5,
                details="Listed in the local threat feed as suspicious.",
                checked_at=checked_at,
            )
            self._cache_set(entry)
            return entry

        if self.provider is not None and getattr(
            self.provider,
            "available",
            True,
        ):
            try:
                result = self.provider.lookup(ip_address)
            except (
                urllib.error.URLError,
                TimeoutError,
                RuntimeError,
                ValueError,
                OSError,
            ) as error:
                entry = self._entry(
                    ip_address,
                    status="unknown",
                    source=getattr(
                        self.provider,
                        "name",
                        "external",
                    ),
                    score=None,
                    details=(
                        "Reputation lookup failed: "
                        f"{type(error).__name__}."
                    ),
                    checked_at=checked_at,
                )
                return entry

            entry = self._entry(
                ip_address,
                status=result.get("status", "unknown"),
                source=getattr(
                    self.provider,
                    "name",
                    "external",
                ),
                score=result.get("score"),
                details=json.dumps(
                    result,
                    default=str,
                ),
                checked_at=checked_at,
            )
            self._cache_set(entry)
            return entry

        entry = self._entry(
            ip_address,
            status="unknown",
            source=None,
            score=None,
            details=(
                "No reputation source has data for this address. "
                "This is not evidence of benign or malicious activity."
            ),
            checked_at=checked_at,
        )
        self._cache_set(entry)
        return entry

    @staticmethod
    def _entry(
        ip_address,
        status,
        source,
        score,
        details,
        checked_at,
    ):
        return {
            "ip": ip_address,
            "status": status,
            "source": source,
            "score": score,
            "details": details,
            "last_checked": checked_at,
        }
