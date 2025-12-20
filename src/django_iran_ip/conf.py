from django.conf import settings
from typing import List, Dict, Any


class IranIPConfig:

    @property
    def STRATEGIES(self) -> List[str]:
        """لیست کلاس‌های استراتژی برای شناسایی IP"""
        return getattr(settings, 'IRAN_IP_STRATEGIES', [
            'django_iran_ip.core.strategies.HeaderStrategy',
            'django_iran_ip.core.strategies.ServiceStrategy',
        ])

    @property
    def SERVICE_URLS(self) -> List[str]:

        return getattr(settings, 'IRAN_IP_SERVICE_URLS', [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
            "https://checkip.amazonaws.com",
            "https://ipinfo.io/ip",
        ])

    @property
    def USE_IRAN_SERVICES(self) -> bool:

        return getattr(settings, 'IRAN_IP_USE_IRAN_SERVICES', True)

    @property
    def ENABLE_CACHE(self) -> bool:

        return getattr(settings, 'IRAN_IP_ENABLE_CACHE', True)

    @property
    def CACHE_DURATION(self) -> int:

        return getattr(settings, 'IRAN_IP_CACHE_DURATION', 3600)

    @property
    def REQUEST_TIMEOUT(self) -> float:

        return getattr(settings, 'IRAN_IP_REQUEST_TIMEOUT', 3.0)

    @property
    def ENABLE_GEOLOCATION(self) -> bool:

        return getattr(settings, 'IRAN_IP_ENABLE_GEOLOCATION', False)

    @property
    def GEOLOCATION_SERVICES(self) -> List[str]:

        return getattr(settings, 'IRAN_IP_GEOLOCATION_SERVICES', [
            "https://ipapi.co/{ip}/json/",
            "https://ipwhois.app/json/{ip}",
            "http://ip-api.com/json/{ip}",
        ])

    @property
    def VALIDATE_IP(self) -> bool:

        return getattr(settings, 'IRAN_IP_VALIDATE_IP', True)

    @property
    def LOG_LEVEL(self) -> str:

        return getattr(settings, 'IRAN_IP_LOG_LEVEL', 'WARNING')

    @property
    def HEADER_PRIORITY(self) -> List[str]:

        return getattr(settings, 'IRAN_IP_HEADER_PRIORITY', [
            'HTTP_AR_REAL_IP',  # ابرآروان
            'HTTP_X_REAL_IP',  # دراک و پروکسی‌های عمومی
            'HTTP_CF_CONNECTING_IP',  # کلودفلر
            'HTTP_X_FORWARDED_FOR',  # استاندارد عمومی
            'HTTP_FORWARDED',  # RFC 7239
            'HTTP_TRUE_CLIENT_IP',  # Akamai و CDN‌های دیگر
            'REMOTE_ADDR'  # اتصال مستقیم
        ])

    @property
    def CHECK_IRAN_IP(self) -> bool:

        return getattr(settings, 'IRAN_IP_CHECK_IRAN_IP', False)

    @property
    def BLOCK_NON_IRAN_IP(self) -> bool:

        return getattr(settings, 'IRAN_IP_BLOCK_NON_IRAN_IP', False)

    @property
    def IRAN_IP_RANGES(self) -> List[str]:

        default_ranges = [
            "2.176.0.0/12", "5.22.0.0/16", "5.23.0.0/16",
            "5.52.0.0/16", "5.53.0.0/16", "31.2.128.0/17",
            "37.32.0.0/13", "37.98.0.0/16", "37.99.0.0/16",
            "46.18.0.0/15", "46.32.0.0/11", "46.100.0.0/14",
            "77.36.128.0/17", "78.38.0.0/15", "79.127.0.0/17",
            "80.66.176.0/20", "80.191.0.0/16", "81.12.0.0/17",
            "82.99.192.0/18", "83.120.0.0/14", "85.15.0.0/18",
            "85.133.128.0/17", "85.185.0.0/16", "86.55.0.0/16",
            "87.107.0.0/16", "88.135.32.0/20", "89.32.0.0/16",
            "89.144.128.0/18", "89.165.0.0/17", "89.196.0.0/16",
            "89.198.0.0/15", "91.92.104.0/21", "91.98.0.0/15",
            "92.38.128.0/21", "92.114.16.0/20", "93.88.0.0/17",
            "94.182.0.0/15", "95.38.0.0/16", "95.80.128.0/18",
        ]
        return getattr(settings, 'IRAN_IP_IRAN_IP_RANGES', default_ranges)

    def get_config_dict(self) -> Dict[str, Any]:

        return {
            'strategies': self.STRATEGIES,
            'service_urls': self.SERVICE_URLS,
            'use_iran_services': self.USE_IRAN_SERVICES,
            'enable_cache': self.ENABLE_CACHE,
            'cache_duration': self.CACHE_DURATION,
            'request_timeout': self.REQUEST_TIMEOUT,
            'enable_geolocation': self.ENABLE_GEOLOCATION,
            'geolocation_services': self.GEOLOCATION_SERVICES,
            'validate_ip': self.VALIDATE_IP,
            'log_level': self.LOG_LEVEL,
            'header_priority': self.HEADER_PRIORITY,
            'check_iran_ip': self.CHECK_IRAN_IP,
            'block_non_iran_ip': self.BLOCK_NON_IRAN_IP,
            'iran_ip_ranges': self.IRAN_IP_RANGES,
        }

    def __repr__(self):
        return f"<IranIPConfig: {len(self.STRATEGIES)} strategies, cache={self.ENABLE_CACHE}>"


conf = IranIPConfig()