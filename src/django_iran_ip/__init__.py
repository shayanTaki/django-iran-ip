"""
Django Iran IP - پکیج حرفه‌ای برای شناسایی و مدیریت IP کاربران ایرانی

این پکیج ابزارهای قدرتمندی برای شناسایی IP کاربران، 
بررسی IP‌های ایرانی، و مدیریت دسترسی بر اساس موقعیت جغرافیایی ارائه می‌دهد.
"""

__version__ = '0.1.0'
__author__ = 'Shayan Taki'
__email__ = 'takishayan@icloud.com'

# Core imports
from django_iran_ip.core.resolver import IPResolver
from django_iran_ip.core.base import BaseIPStrategy
from django_iran_ip.core.strategies import (
    HeaderStrategy,
    ServiceStrategy,
    SocketStrategy,
    CachedServiceStrategy,
    FallbackStrategy,
)

# Validator imports
from django_iran_ip.core.validators import (
    IPValidator,
    IPGeolocation,
    IranIPChecker,
)

# Config import
from django_iran_ip.conf import conf

# Django contrib imports (optional)
try:
    from django_iran_ip.contrib.django.middleware import (
        IranIPMiddleware,
        IranIPLoggingMiddleware,
        IranIPRateLimitMiddleware,
    )
    from django_iran_ip.contrib.django.utils import get_client_ip

    __all__ = [
        # Version
        '__version__',

        # Core
        'IPResolver',
        'BaseIPStrategy',

        # Strategies
        'HeaderStrategy',
        'ServiceStrategy',
        'SocketStrategy',
        'CachedServiceStrategy',
        'FallbackStrategy',

        # Validators
        'IPValidator',
        'IPGeolocation',
        'IranIPChecker',

        # Config
        'conf',

        # Django
        'IranIPMiddleware',
        'IranIPLoggingMiddleware',
        'IranIPRateLimitMiddleware',
        'get_client_ip',
    ]
except ImportError:
    # Django not installed
    __all__ = [
        # Version
        '__version__',

        # Core
        'IPResolver',
        'BaseIPStrategy',

        # Strategies
        'HeaderStrategy',
        'ServiceStrategy',
        'SocketStrategy',
        'CachedServiceStrategy',
        'FallbackStrategy',

        # Validators
        'IPValidator',
        'IPGeolocation',
        'IranIPChecker',

        # Config
        'conf',
    ]


def get_version():

    return __version__


def get_package_info():

    return {
        'name': 'django-iran-ip',
        'version': __version__,
        'author': __author__,
        'email': __email__,
        'description': 'A professional Django package for IP detection with Iran network support',
    }