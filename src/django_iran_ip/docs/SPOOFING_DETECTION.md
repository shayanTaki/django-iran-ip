# IP Spoofing Detection

این فیچر یک سیستم پیشرفته و چندلایه برای تشخیص تلاش‌های جعل IP (IP Spoofing) ارائه می‌دهد.

## 🎯 هدف

جلوگیری از حملات مبتنی بر جعل IP شامل:
- Header Manipulation
- Proxy Chain Abuse
- IP Forgery
- CDN Bypass Attempts
- Botnet Traffic
- Distributed Attacks

## 🔍 روش‌های تشخیص

### 1. **تحلیل تناقض هدرها (Header Inconsistency)**
```
Severity: HIGH | Confidence: 0.7

بررسی تناقض بین IP های گزارش شده توسط هدرهای مختلف.
مثال: X-Real-IP می‌گوید 1.2.3.4 اما CF-Connecting-IP می‌گوید 5.6.7.8
```

### 2. **تشخیص IP خصوصی در هدرهای عمومی (Private IP Leakage)**
```
Severity: CRITICAL | Confidence: 0.95

IP های خصوصی نباید در هدرهای CDN ظاهر شوند.
مثال: CF-Connecting-IP: 192.168.1.1 ❌
```

### 3. **تحلیل زنجیره پروکسی (Proxy Chain Analysis)**
```
Severity: MEDIUM-HIGH | Confidence: 0.6-0.9

- زنجیره بیش از 5 hop مشکوک است
- وجود IP نامعتبر در زنجیره
- تکرار IP در زنجیره (حلقه)
```

### 4. **تشخیص IP های رزرو شده (Reserved IPs)**
```
Severity: CRITICAL | Confidence: 1.0

استفاده از IP های رزرو شده:
- 0.0.0.0, 255.255.255.255
- 127.x.x.x (loopback)
- 169.254.x.x (link-local)
```

### 5. **تحلیل رفتاری (Behavioral Analysis)**
```
Severity: HIGH | Confidence: 0.8

- نرخ درخواست غیرعادی (>1000 req/hour)
- تغییر User-Agent برای همان IP
- الگوهای مشکوک
```

### 6. **مقایسه جغرافیایی (Geolocation Analysis)**
```
Severity: HIGH | Confidence: 0.75

تناقض در موقعیت جغرافیایی IP های مختلف
مثال: یک IP از ایران و یکی از آمریکا
```

## 📊 سیستم امتیازدهی

```python
Risk Score = Σ(Severity_Weight × Confidence)

Severity Weights:
- LOW: 10 points
- MEDIUM: 25 points
- HIGH: 50 points
- CRITICAL: 100 points

Total Risk Score: 0-100
```

### اقدامات پیشنهادی:

| Risk Score | Action | توضیحات |
|-----------|--------|---------|
| 0-29 | **allow** | درخواست امن |
| 30-49 | **monitor** | نظارت بیشتر |
| 50-79 | **challenge** | CAPTCHA / 2FA |
| 80-100 | **block** | مسدود کردن |

## 🚀 نصب و راه‌اندازی

### 1. فعال‌سازی در تنظیمات

```python
# settings.py

# فعال‌سازی تشخیص IP Spoofing
IRAN_IP_ENABLE_SPOOFING_DETECTION = True

# حالت امن: فقط لاگ می‌کند، مسدود نمی‌کند
IRAN_IP_SPOOFING_LOG_ONLY = True

# مسدود کردن خودکار (خطرناک!)
IRAN_IP_SPOOFING_AUTO_BLOCK = False

# آستانه risk score برای تشخیص مشکوک
IRAN_IP_SPOOFING_THRESHOLD = 70.0

# تحلیل رفتاری (نیاز به memory دارد)
IRAN_IP_SPOOFING_ENABLE_BEHAVIORAL = True

# تحلیل جغرافیایی (نیاز به API دارد)
IRAN_IP_SPOOFING_ENABLE_GEOLOCATION = False

# حداکثر طول زنجیره پروکسی
IRAN_IP_SPOOFING_MAX_PROXY_CHAIN = 5

# حد مجاز درخواست در ساعت
IRAN_IP_SPOOFING_RATE_LIMIT = 1000

# IP های قابل اعتماد (CDN ها)
IRAN_IP_SPOOFING_TRUSTED_PROXIES = [
    '2.144.0.0/13',  # Arvancloud
    '103.21.244.0/22',  # Cloudflare
]

# Whitelist (معاف از بررسی)
IRAN_IP_SPOOFING_WHITELIST_IPS = [
    '1.2.3.4',
]

# Blacklist (مسدود شده)
IRAN_IP_SPOOFING_BLACKLIST_IPS = [
    '5.6.7.8',
]
```

### 2. اضافه کردن Middleware

```python
MIDDLEWARE = [
    # ...
    'django_iran_ip.core.spoofing.SpoofingProtectionMiddleware',
    # ...
]
```

### 3. استفاده در View

```python
from django.http import JsonResponse

def my_view(request):
    # دسترسی به تحلیل spoofing
    if hasattr(request, 'spoofing_analysis'):
        analysis = request.spoofing_analysis
        
        return JsonResponse({
            'is_suspicious': analysis.is_suspicious,
            'risk_score': analysis.risk_score,
            'recommended_action': analysis.recommended_action,
            'signals': [
                {
                    'type': s.type,
                    'severity': s.severity,
                    'description': s.description
                }
                for s in analysis.signals
            ]
        })
```

## 📝 استفاده دستی

### تحلیل یک درخواست

```python
from django_iran_ip.core.spoofing import IPSpoofingDetector

detector = IPSpoofingDetector(
    enable_behavioral=True,
    enable_geolocation=True
)

# استخراج IP ها
extracted_ips = {
    'HTTP_X_REAL_IP': '1.2.3.4',
    'HTTP_CF_CONNECTING_IP': '1.2.3.4',
    'REMOTE_ADDR': '1.2.3.4'
}

# تحلیل
analysis = detector.analyze(request, extracted_ips)

print(f"Risk Score: {analysis.risk_score}")
print(f"Is Suspicious: {analysis.is_suspicious}")
print(f"Action: {analysis.recommended_action}")

for signal in analysis.signals:
    print(f"[{signal.severity}] {signal.description}")
```

### استفاده در IPResolver

```python
from django_iran_ip.core.resolver import IPResolver

# با فعال‌سازی تشخیص spoofing
resolver = IPResolver(enable_spoofing_detection=True)

# دریافت IP با بررسی امنیت
ip = resolver.get_client_ip(request)

# دریافت اطلاعات کامل
info = resolver.get_client_info(request)
print(info['spoofing_analysis'])
```

## 🔒 سناریوهای حمله و دفاع

### حمله 1: Header Manipulation
```
🔴 حمله:
X-Real-IP: 1.2.3.4 (هکر)
CF-Connecting-IP: 8.8.8.8 (واقعی)

✅ دفاع:
- تشخیص تناقض
- Risk Score: 50 → Challenge
```

### حمله 2: Private IP Injection
```
🔴 حمله:
CF-Connecting-IP: 192.168.1.1

✅ دفاع:
- تشخیص IP خصوصی در CDN
- Risk Score: 95 → Block
```

### حمله 3: Proxy Chain Abuse
```
🔴 حمله:
X-Forwarded-For: 1.1.1.1, 2.2.2.2, 3.3.3.3, ..., 10.10.10.10

✅ دفاع:
- زنجیره بیش از حد طولانی
- Risk Score: 60 → Challenge
```

### حمله 4: Rate Limiting Bypass
```
🔴 حمله:
2000 درخواست در 5 دقیقه

✅ دفاع:
- تحلیل رفتاری
- Risk Score: 80 → Block
```

## 📈 مانیتورینگ و لاگ

### لاگ‌های خودکار

```python
import logging

logger = logging.getLogger('django_iran_ip')
logger.setLevel(logging.INFO)

# خروجی:
# WARNING - Suspicious IP detected: risk=85.5, signals=['header_inconsistency', 'private_ip_in_cdn_header']
```

### Dashboard سفارشی

```python
from django_iran_ip.core.spoofing import IPSpoofingDetector

def security_dashboard(request):
    detector = IPSpoofingDetector()
    
    # آمار کلی
    stats = {
        'total_requests': len(detector._request_history),
        'suspicious_ips': sum(
            1 for ip, history in detector._request_history.items()
            if len(history) > 1000
        )
    }
    
    return render(request, 'dashboard.html', stats)
```

## ⚠️ توجهات مهم

### 1. **False Positive**
```
برخی سناریوها ممکن است به اشتباه مشکوک تشخیص داده شوند:
- کاربران پشت VPN
- شبکه‌های بزرگ سازمانی
- استفاده از چند CDN

راه حل: استفاده از Whitelist و تنظیم دقیق threshold
```

### 2. **Performance**
```
تحلیل رفتاری نیاز به نگهداری state در memory دارد.

برای traffic بالا:
- از Redis استفاده کنید
- enable_behavioral = False
- فقط لاگ کنید، مسدود نکنید
```

### 3. **Production**
```
مراحل راه‌اندازی در production:

1. شروع با LOG_ONLY = True
2. مانیتور کردن برای 1 هفته
3. تنظیم threshold بر اساس داده
4. فعال‌سازی تدریجی AUTO_BLOCK
```

## 🧪 تست

```bash
# اجرای تست‌ها
python -m unittest tests/test_spoofing.py

# تست سناریوهای خاص
python manage.py test django_iran_ip.tests.test_spoofing.TestIPSpoofingDetector.test_private_ip_in_cdn_header
```

## 🔧 عیب‌یابی

### مشکل: همه درخواست‌ها مشکوک تشخیص داده می‌شوند

```python
# کاهش threshold
IRAN_IP_SPOOFING_THRESHOLD = 90.0

# بررسی لاگ‌ها
logger.setLevel(logging.DEBUG)
```

### مشکل: درخواست‌های مشروع مسدود می‌شوند

```python
# اضافه کردن به whitelist
IRAN_IP_SPOOFING_WHITELIST_IPS = ['1.2.3.4']

# یا trusted proxies
IRAN_IP_SPOOFING_TRUSTED_PROXIES = ['10.0.0.0/8']
```

## 📚 مراجع

- [OWASP: IP Spoofing](https://owasp.org/www-community/attacks/IP_Spoofing)
- [RFC 7239: Forwarded HTTP Extension](https://tools.ietf.org/html/rfc7239)
- [Cloudflare: What is IP spoofing?](https://www.cloudflare.com/learning/ddos/glossary/ip-spoofing/)

---

**نکته امنیتی:** این سیستم یک لایه دفاعی است، نه راه‌حل کامل. همیشه از روش‌های امنیتی دیگر نیز استفاده کنید.