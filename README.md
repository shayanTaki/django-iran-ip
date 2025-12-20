# Django Iran IP

یک پکیج حرفه‌ای Django برای شناسایی و مدیریت IP کاربران، با پشتیبانی ویژه از شبکه‌های ایرانی و CDNهای محلی.

## ویژگی‌ها

- ✅ شناسایی خودکار IP از هدرهای مختلف (Arvancloud، Cloudflare، و...)
- ✅ پشتیبانی از CDNهای ایرانی (ابرآروان، دراک)
- ✅ Fallback به سرویس‌های خارجی در صورت عدم دسترسی به هدر
- ✅ کش هوشمند برای کاهش درخواست‌های API
- ✅ شناسایی IP‌های ایرانی
- ✅ Geolocation و شناسایی ISP
- ✅ Rate limiting بر اساس IP
- ✅ اعتبارسنجی IP
- ✅ پشتیبانی کامل از IPv4
- ✅ Middleware آماده برای Django
- ✅ سازگار با Django 4.2+ و Python 3.10+

## نصب

```bash
pip install django-iran-ip
```

یا با Poetry:

```bash
poetry add django-iran-ip
```

## راه‌اندازی سریع

### 1. اضافه کردن به INSTALLED_APPS

```python
# settings.py
INSTALLED_APPS = [
    # ...
    'django_iran_ip',
]
```

### 2. اضافه کردن Middleware

```python
# settings.py
MIDDLEWARE = [
    # ...
    'django_iran_ip.contrib.django.middleware.IranIPMiddleware',
]
```

### 3. استفاده در View

```python
from django.http import JsonResponse

def my_view(request):
    client_ip = request.client_ip
    
    return JsonResponse({
        'ip': client_ip,
        'is_valid': request.client_ip_valid,
        'type': request.client_ip_type,
        'is_iran': getattr(request, 'is_iran_ip', None),
    })
```

## استفاده بدون Middleware

```python
from django_iran_ip.contrib.django.utils import get_client_ip

def my_view(request):
    client_ip = get_client_ip(request)
    return JsonResponse({'ip': client_ip})
```

## تنظیمات پیشرفته

```python
# settings.py

# استراتژی‌های شناسایی IP (به ترتیب اولویت)
IRAN_IP_STRATEGIES = [
    'django_iran_ip.core.strategies.HeaderStrategy',
    'django_iran_ip.core.strategies.ServiceStrategy',
]

# سرویس‌های خارجی برای دریافت IP
IRAN_IP_SERVICE_URLS = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
]

# استفاده از سرویس‌های ایرانی
IRAN_IP_USE_IRAN_SERVICES = True

# فعال‌سازی کش
IRAN_IP_ENABLE_CACHE = True
IRAN_IP_CACHE_DURATION = 3600  # 1 ساعت

# تایم‌اوت درخواست‌ها
IRAN_IP_REQUEST_TIMEOUT = 3.0

# اعتبارسنجی IP
IRAN_IP_VALIDATE_IP = True

# بررسی IP ایرانی
IRAN_IP_CHECK_IRAN_IP = True

# مسدود کردن IP‌های غیر ایرانی (اختیاری)
IRAN_IP_BLOCK_NON_IRAN_IP = False

# فعال‌سازی Geolocation
IRAN_IP_ENABLE_GEOLOCATION = True

# سطح لاگ
IRAN_IP_LOG_LEVEL = 'INFO'  # DEBUG, INFO, WARNING, ERROR

# اولویت هدرها
IRAN_IP_HEADER_PRIORITY = [
    'HTTP_AR_REAL_IP',       # ابرآروان
    'HTTP_X_REAL_IP',        # دراک
    'HTTP_CF_CONNECTING_IP', # کلودفلر
    'HTTP_X_FORWARDED_FOR',
    'REMOTE_ADDR',
]
```

## استفاده پیشرفته

### 1. شناسایی IP ایرانی

```python
from django_iran_ip.core.validators import IranIPChecker

checker = IranIPChecker()
is_iran = checker.is_iran_ip("5.22.10.20")  # True
print(f"IP is from Iran: {is_iran}")
```

### 2. دریافت اطلاعات جغرافیایی

```python
from django_iran_ip.core.validators import IPGeolocation

geo = IPGeolocation()
info = geo.get_location("8.8.8.8")
print(info)
# {
#     'country': 'United States',
#     'country_code': 'US',
#     'city': 'Mountain View',
#     'isp': 'Google LLC',
#     'timezone': 'America/Los_Angeles'
# }
```

### 3. اعتبارسنجی IP

```python
from django_iran_ip.core.validators import IPValidator

validator = IPValidator()
print(validator.is_valid_ipv4("192.168.1.1"))  # True
print(validator.is_private_ip("192.168.1.1"))  # True
print(validator.get_ip_type("8.8.8.8"))  # "public"
```

### 4. استفاده از استراتژی‌های سفارشی

```python
from django_iran_ip.core.resolver import IPResolver
from django_iran_ip.core.strategies import HeaderStrategy, ServiceStrategy

# استفاده از استراتژی خاص
resolver = IPResolver(strategies=[
    HeaderStrategy(),
    ServiceStrategy(timeout=5.0)
])

ip = resolver.get_client_ip(request)
```

### 5. دریافت اطلاعات کامل

```python
from django_iran_ip.core.resolver import IPResolver

resolver = IPResolver()
info = resolver.get_client_info(request)
print(info)
# {
#     'ip': '5.22.10.20',
#     'strategy_used': 'HeaderStrategy',
#     'is_valid': True
# }
```

## Middleware‌های اضافی

### 1. Logging Middleware

```python
# settings.py
MIDDLEWARE = [
    'django_iran_ip.contrib.django.middleware.IranIPLoggingMiddleware',
    # ...
]
```

### 2. Rate Limiting Middleware

```python
# settings.py
MIDDLEWARE = [
    'django_iran_ip.contrib.django.middleware.IranIPRateLimitMiddleware',
    # ...
]

# تنظیمات Rate Limit
IRAN_IP_RATE_LIMIT = 100  # تعداد درخواست
IRAN_IP_RATE_PERIOD = 3600  # بازه زمانی (ثانیه)
```

## مثال‌های کاربردی

### محدود کردن دسترسی به IP‌های ایرانی

```python
from django.http import HttpResponseForbidden
from django_iran_ip.core.validators import IranIPChecker

def iran_only_view(request):
    checker = IranIPChecker()
    
    if not checker.is_iran_ip(request.client_ip):
        return HttpResponseForbidden("فقط کاربران ایرانی مجاز هستند")
    
    return render(request, 'template.html')
```

### نمایش اطلاعات کاربر

```python
def user_info_view(request):
    context = {
        'ip': request.client_ip,
        'is_iran': getattr(request, 'is_iran_ip', False),
        'geo': getattr(request, 'client_geo', {}),
    }
    return render(request, 'user_info.html', context)
```

## CDN‌های پشتیبانی شده

- ✅ ابرآروان (Arvancloud)
- ✅ دراک (Derak)
- ✅ کلودفلر (Cloudflare)
- ✅ Akamai
- ✅ و سایر CDNهای استاندارد

## عیب‌یابی

### IP شناسایی نمی‌شود

1. بررسی کنید Middleware به درستی اضافه شده است
2. سطح لاگ را به `DEBUG` تغییر دهید:
   ```python
   IRAN_IP_LOG_LEVEL = 'DEBUG'
   ```
3. در لاگ‌ها بررسی کنید کدام استراتژی در حال اجرا است

### IP اشتباه شناسایی می‌شود

اولویت هدرها را بررسی کنید. برای CDN‌های ایرانی:

```python
IRAN_IP_HEADER_PRIORITY = [
    'HTTP_AR_REAL_IP',       # ابرآروان را اول قرار دهید
    'HTTP_X_REAL_IP',
    'HTTP_CF_CONNECTING_IP',
    'REMOTE_ADDR',
]
```

## مشارکت

مشارکت‌ها همیشه خوش‌آمد هستند! لطفاً:

1. مخزن را Fork کنید
2. یک branch جدید بسازید (`git checkout -b feature/amazing-feature`)
3. تغییرات خود را commit کنید (`git commit -m 'Add amazing feature'`)
4. به branch خود push کنید (`git push origin feature/amazing-feature`)
5. یک Pull Request باز کنید

## لایسنس

MIT License - برای جزئیات بیشتر فایل [LICENSE](LICENSE) را ببینید.

## پشتیبانی

- 📧 Email: takishayan@icloud.com
- 🐛 Issues: [GitHub Issues](https://github.com/shayanTaki/django-iran-ip/issues)
- 📖 Documentation: [Full Documentation](https://github.com/shayanTaki/django-iran-ip/wiki)

## تغییرات نسخه‌ها

### نسخه 0.1.0

- اولین انتشار
- پشتیبانی از شناسایی IP از هدرهای مختلف
- Fallback به سرویس‌های API
- پشتیبانی از CDN‌های ایرانی
- کش هوشمند
- Middleware آماده

---

ساخته شده با ❤️ برای جامعه توسعه‌دهندگان ایرانی