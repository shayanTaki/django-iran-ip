from django.conf import settings
from typing import List, Dict, Any


class IranIPConfig:
    """مدیریت تنظیمات پکیج در فایل settings.py کاربر"""
    
    @property
    def STRATEGIES(self) -> List[str]:
        """لیست کلاس‌های استراتژی برای شناسایی IP"""
        return getattr(settings, 'IRAN_IP_STRATEGIES', [
            'django_iran_ip.core.strategies.HeaderStrategy',
            'django_iran_ip.core.strategies.ServiceStrategy',
        ])
    
    @property
    def SERVICE_URLS(self) -> List[str]:
        """لیست URLهای سرویس برای دریافت IP عمومی"""
        return getattr(settings, 'IRAN_IP_SERVICE_URLS', [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
            "https://checkip.amazonaws.com",
            "https://ipinfo.io/ip",
        ])
    
    @property
    def USE_IRAN_SERVICES(self) -> bool:
        """استفاده از سرویس‌های ایرانی برای دریافت IP"""
        return getattr(settings, 'IRAN_IP_USE_IRAN_SERVICES', True)
    
    @property
    def ENABLE_CACHE(self) -> bool:
        """فعال‌سازی کش برای ServiceStrategy"""
        return getattr(settings, 'IRAN_IP_ENABLE_CACHE', True)
    
    @property
    def CACHE_DURATION(self) -> int:
        """مدت زمان کش به ثانیه (پیش‌فرض: 1 ساعت)"""
        return getattr(settings, 'IRAN_IP_CACHE_DURATION', 3600)
    
    @property
    def REQUEST_TIMEOUT(self) -> float:
        """تایم‌اوت برای درخواست‌های HTTP به ثانیه"""
        return getattr(settings, 'IRAN_IP_REQUEST_TIMEOUT', 3.0)
    
    @property
    def ENABLE_GEOLOCATION(self) -> bool:
        """فعال‌سازی شناسایی موقعیت جغرافیایی"""
        return getattr(settings, 'IRAN_IP_ENABLE_GEOLOCATION', False)
    
    @property
    def GEOLOCATION_SERVICES(self) -> List[str]:
        """لیست سرویس‌های geolocation"""
        return getattr(settings, 'IRAN_IP_GEOLOCATION_SERVICES', [
            "https://ipapi.co/{ip}/json/",
            "https://ipwhois.app/json/{ip}",
            "http://ip-api.com/json/{ip}",
        ])
    
    @property
    def VALIDATE_IP(self) -> bool:
        """اعتبارسنجی IP قبل از برگرداندن"""
        return getattr(settings, 'IRAN_IP_VALIDATE_IP', True)
    
    @property
    def LOG_LEVEL(self) -> str:
        """سطح لاگ برای django-iran-ip"""
        return getattr(settings, 'IRAN_IP_LOG_LEVEL', 'WARNING')
    
    @property
    def HEADER_PRIORITY(self) -> List[str]:
        """اولویت هدرها برای استخراج IP"""
        return getattr(settings, 'IRAN_IP_HEADER_PRIORITY', [
            'HTTP_AR_REAL_IP',
            'HTTP_X_REAL_IP',
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'HTTP_TRUE_CLIENT_IP',
            'REMOTE_ADDR'
        ])
    
    @property
    def CHECK_IRAN_IP(self) -> bool:
        """بررسی اینکه IP از ایران است یا خیر"""
        return getattr(settings, 'IRAN_IP_CHECK_IRAN_IP', False)
    
    @property
    def BLOCK_NON_IRAN_IP(self) -> bool:
        """مسدود کردن IP‌های غیر ایرانی"""
        return getattr(settings, 'IRAN_IP_BLOCK_NON_IRAN_IP', False)
    
    # ========== تنظیمات IP Spoofing Detection ==========
    
    @property
    def ENABLE_SPOOFING_DETECTION(self) -> bool:
        """فعال‌سازی تشخیص IP Spoofing"""
        return getattr(settings, 'IRAN_IP_ENABLE_SPOOFING_DETECTION', False)
    
    @property
    def SPOOFING_AUTO_BLOCK(self) -> bool:
        """مسدود کردن خودکار IP های مشکوک"""
        return getattr(settings, 'IRAN_IP_SPOOFING_AUTO_BLOCK', False)
    
    @property
    def SPOOFING_LOG_ONLY(self) -> bool:
        """فقط لاگ کردن بدون مسدود کردن (حالت safe)"""
        return getattr(settings, 'IRAN_IP_SPOOFING_LOG_ONLY', True)
    
    @property
    def SPOOFING_THRESHOLD(self) -> float:
        """آستانه risk score برای تشخیص به عنوان مشکوک (0-100)"""
        return getattr(settings, 'IRAN_IP_SPOOFING_THRESHOLD', 70.0)
    
    @property
    def SPOOFING_ENABLE_BEHAVIORAL(self) -> bool:
        """فعال‌سازی تحلیل رفتاری در تشخیص spoofing"""
        return getattr(settings, 'IRAN_IP_SPOOFING_ENABLE_BEHAVIORAL', True)
    
    @property
    def SPOOFING_ENABLE_GEOLOCATION(self) -> bool:
        """فعال‌سازی تحلیل جغرافیایی در تشخیص spoofing"""
        return getattr(settings, 'IRAN_IP_SPOOFING_ENABLE_GEOLOCATION', False)
    
    @property
    def SPOOFING_MAX_PROXY_CHAIN(self) -> int:
        """حداکثر طول زنجیره پروکسی مجاز"""
        return getattr(settings, 'IRAN_IP_SPOOFING_MAX_PROXY_CHAIN', 5)
    
    @property
    def SPOOFING_RATE_LIMIT(self) -> int:
        """حد مجاز درخواست در ساعت برای هر IP"""
        return getattr(settings, 'IRAN_IP_SPOOFING_RATE_LIMIT', 1000)
    
    @property
    def SPOOFING_TRUSTED_PROXIES(self) -> List[str]:
        """لیست IP های پروکسی قابل اعتماد (CDN ها)"""
        return getattr(settings, 'IRAN_IP_SPOOFING_TRUSTED_PROXIES', [
            # رنج‌های IP ابرآروان
            '2.144.0.0/13',
            '5.160.0.0/14',
            # رنج‌های IP کلودفلر
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            # می‌توان رنج‌های دیگر را اضافه کرد
        ])
    
    @property
    def SPOOFING_WHITELIST_IPS(self) -> List[str]:
        """لیست IP های مجاز که از بررسی spoofing معاف هستند"""
        return getattr(settings, 'IRAN_IP_SPOOFING_WHITELIST_IPS', [])
    
    @property
    def SPOOFING_BLACKLIST_IPS(self) -> List[str]:
        """لیست IP های مسدود شده"""
        return getattr(settings, 'IRAN_IP_SPOOFING_BLACKLIST_IPS', [])
    
    # ========== انتهای تنظیمات Spoofing ==========
    
    @property
    def IRAN_IP_RANGES(self) -> List[str]:
        """رنج‌های IP ایران (CIDR notation)"""
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
        """دریافت تمام تنظیمات به صورت دیکشنری"""
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
            
            # Spoofing settings
            'enable_spoofing_detection': self.ENABLE_SPOOFING_DETECTION,
            'spoofing_auto_block': self.SPOOFING_AUTO_BLOCK,
            'spoofing_log_only': self.SPOOFING_LOG_ONLY,
            'spoofing_threshold': self.SPOOFING_THRESHOLD,
            'spoofing_enable_behavioral': self.SPOOFING_ENABLE_BEHAVIORAL,
            'spoofing_enable_geolocation': self.SPOOFING_ENABLE_GEOLOCATION,
            'spoofing_max_proxy_chain': self.SPOOFING_MAX_PROXY_CHAIN,
            'spoofing_rate_limit': self.SPOOFING_RATE_LIMIT,
            'spoofing_trusted_proxies': self.SPOOFING_TRUSTED_PROXIES,
            'spoofing_whitelist_ips': self.SPOOFING_WHITELIST_IPS,
            'spoofing_blacklist_ips': self.SPOOFING_BLACKLIST_IPS,
        }
    
    def __repr__(self):
        spoofing_status = "enabled" if self.ENABLE_SPOOFING_DETECTION else "disabled"
        return f"<IranIPConfig: spoofing={spoofing_status}, strategies={len(self.STRATEGIES)}>"



conf = IranIPConfig()