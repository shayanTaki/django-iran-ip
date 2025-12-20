import httpx
import socket
from typing import Optional, List
from .base import BaseIPStrategy


class HeaderStrategy(BaseIPStrategy):

    HEADERS = [
        'HTTP_AR_REAL_IP',  # ابرآروان
        'HTTP_X_REAL_IP',  # دراک و پروکسی‌های عمومی
        'HTTP_CF_CONNECTING_IP',  # کلودفلر
        'HTTP_X_FORWARDED_FOR',  # استاندارد عمومی
        'HTTP_FORWARDED',  # RFC 7239
        'HTTP_TRUE_CLIENT_IP',  # Akamai و CDN‌های دیگر
        'REMOTE_ADDR'  # اتصال مستقیم
    ]

    def get_ip(self, request=None) -> Optional[str]:
        if not request:
            return None

        for header in self.HEADERS:
            value = request.META.get(header)
            if value:

                ip = value.split(',')[0].strip()
                if self._is_valid_ip(ip):
                    return ip
        return None

    def _is_valid_ip(self, ip: str) -> bool:

        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False


class ServiceStrategy(BaseIPStrategy):


    DEFAULT_SERVICES = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com",
        "https://ipinfo.io/ip",
    ]

    # سرویس‌های ایرانی که در ایران فیلتر نیستند
    IRAN_SERVICES = [
        "https://api.myip.com",
        "https://ipapi.co/ip/",
    ]

    def __init__(self, services: List[str] = None, timeout: float = 3.0, use_iran_services: bool = True):

        self.timeout = timeout

        if services:
            self.services = services
        else:
            self.services = self.DEFAULT_SERVICES.copy()
            if use_iran_services:
                self.services.extend(self.IRAN_SERVICES)

    def get_ip(self, request=None) -> Optional[str]:
        for url in self.services:
            try:
                with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                    response = client.get(url)
                    if response.status_code == 200:
                        ip = response.text.strip()
                        if self._is_valid_ip(ip):
                            return ip
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
                continue
            except Exception:
                continue
        return None

    def _is_valid_ip(self, ip: str) -> bool:

        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False


class SocketStrategy(BaseIPStrategy):


    def __init__(self, test_host: str = "8.8.8.8", test_port: int = 80):

        self.test_host = test_host
        self.test_port = test_port

    def get_ip(self, request=None) -> Optional[str]:

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.test_host, self.test_port))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None


class CachedServiceStrategy(BaseIPStrategy):


    def __init__(self, base_strategy: BaseIPStrategy = None, cache_duration: int = 3600):

        self.base_strategy = base_strategy or ServiceStrategy()
        self.cache_duration = cache_duration
        self._cached_ip = None
        self._cache_time = None

    def get_ip(self, request=None) -> Optional[str]:
        import time

        current_time = time.time()


        if (self._cached_ip and self._cache_time and
                (current_time - self._cache_time) < self.cache_duration):
            return self._cached_ip


        ip = self.base_strategy.get_ip(request)

        if ip:
            self._cached_ip = ip
            self._cache_time = current_time

        return ip


class FallbackStrategy(BaseIPStrategy):


    def __init__(self, strategies: List[BaseIPStrategy]):

        self.strategies = strategies

    def get_ip(self, request=None) -> Optional[str]:
        for strategy in self.strategies:
            ip = strategy.get_ip(request)
            if ip:
                return ip
        return None