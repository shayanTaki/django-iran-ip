import ipaddress
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class SpoofingSignal:
    """سیگنال احتمالی IP Spoofing"""
    type: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    confidence: float  # 0.0 to 1.0
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class SpoofingAnalysis:
    """نتیجه تحلیل کامل Spoofing"""
    is_suspicious: bool
    risk_score: float  # 0.0 to 100.0
    signals: List[SpoofingSignal] = field(default_factory=list)
    recommended_action: str = "allow"  # allow, monitor, block
    
    def add_signal(self, signal: SpoofingSignal):
        """اضافه کردن سیگنال جدید"""
        self.signals.append(signal)
        self._recalculate_risk()
    
    def _recalculate_risk(self):
        """محاسبه مجدد امتیاز خطر"""
        if not self.signals:
            self.risk_score = 0.0
            self.is_suspicious = False
            return
        
        severity_weights = {
            'low': 10,
            'medium': 25,
            'high': 50,
            'critical': 100
        }
        
        total_score = sum(
            severity_weights.get(s.severity, 0) * s.confidence 
            for s in self.signals
        )
        
        # نرمال‌سازی به بازه 0-100
        self.risk_score = min(100.0, total_score)
        self.is_suspicious = self.risk_score > 30.0
        
        # تعیین اقدام پیشنهادی
        if self.risk_score >= 80:
            self.recommended_action = "block"
        elif self.risk_score >= 50:
            self.recommended_action = "challenge"  # CAPTCHA, etc.
        elif self.risk_score >= 30:
            self.recommended_action = "monitor"
        else:
            self.recommended_action = "allow"


class IPSpoofingDetector:
   
    
    def __init__(self, enable_behavioral: bool = True, enable_geolocation: bool = True):
        """
        Args:
            enable_behavioral: فعال‌سازی تحلیل رفتاری
            enable_geolocation: فعال‌سازی مقایسه جغرافیایی
        """
        self.enable_behavioral = enable_behavioral
        self.enable_geolocation = enable_geolocation
        
        # ذخیره‌سازی موقت برای تحلیل رفتاری
        self._request_history: Dict[str, List[datetime]] = defaultdict(list)
        self._ip_fingerprints: Dict[str, str] = {}
        
    def analyze(self, request, extracted_ips: Dict[str, Optional[str]]) -> SpoofingAnalysis:
        
        analysis = SpoofingAnalysis(is_suspicious=False, risk_score=0.0)
        
        # 1. بررسی تناقض در هدرها
        self._check_header_inconsistency(request, extracted_ips, analysis)
        
        # 2. بررسی IP های خصوصی در جای نادرست
        self._check_private_ip_leakage(extracted_ips, analysis)
        
        # 3. تحلیل زنجیره پروکسی
        self._check_proxy_chain(request, extracted_ips, analysis)
        
        # 4. بررسی IP های رزرو شده و مشکوک
        self._check_reserved_ips(extracted_ips, analysis)
        
        # 5. تحلیل رفتاری (اگر فعال باشد)
        if self.enable_behavioral:
            self._behavioral_analysis(request, extracted_ips, analysis)
        
        # 6. مقایسه Geolocation (اگر فعال باشد)
        if self.enable_geolocation:
            self._geolocation_analysis(extracted_ips, analysis)
        
        # 7. بررسی fingerprint درخواست
        self._fingerprint_analysis(request, extracted_ips, analysis)
        
        logger.info(
            f"Spoofing analysis: risk={analysis.risk_score:.2f}, "
            f"signals={len(analysis.signals)}, action={analysis.recommended_action}"
        )
        
        return analysis
    
    def _check_header_inconsistency(
        self, 
        request, 
        extracted_ips: Dict[str, Optional[str]], 
        analysis: SpoofingAnalysis
    ):
        """بررسی تناقض در هدرهای مختلف IP"""
        headers_with_ip = [
            (h, ip) for h, ip in extracted_ips.items() 
            if ip and h != 'REMOTE_ADDR'
        ]
        
        if len(headers_with_ip) < 2:
            return
        
        unique_ips = set(ip for _, ip in headers_with_ip)
        
        # اگر IPهای مختلفی وجود دارد (به جز در X-Forwarded-For)
        if len(unique_ips) > 1:
            # بررسی که آیا این تناقض قابل توجیه است
            has_forwarded = any('FORWARDED' in h for h, _ in headers_with_ip)
            
            if not has_forwarded:
                analysis.add_signal(SpoofingSignal(
                    type='header_inconsistency',
                    severity='high',
                    confidence=0.7,
                    description='تناقض در IPهای گزارش شده توسط هدرهای مختلف',
                    evidence={
                        'headers': headers_with_ip,
                        'unique_ips': list(unique_ips)
                    }
                ))
    
    def _check_private_ip_leakage(
        self, 
        extracted_ips: Dict[str, Optional[str]], 
        analysis: SpoofingAnalysis
    ):
        """بررسی نشت IP های خصوصی در جاهای نامناسب"""
        suspicious_headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_AR_REAL_IP',
            'HTTP_TRUE_CLIENT_IP'
        ]
        
        for header in suspicious_headers:
            ip = extracted_ips.get(header)
            if ip and self._is_private_ip(ip):
                analysis.add_signal(SpoofingSignal(
                    type='private_ip_in_cdn_header',
                    severity='critical',
                    confidence=0.95,
                    description=f'IP خصوصی در هدر CDN: {header}',
                    evidence={'header': header, 'ip': ip}
                ))
    
    def _check_proxy_chain(
        self, 
        request, 
        extracted_ips: Dict[str, Optional[str]], 
        analysis: SpoofingAnalysis
    ):
        """تحلیل زنجیره پروکسی"""
        x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
        
        if not x_forwarded:
            return
        
        ips = [ip.strip() for ip in x_forwarded.split(',')]
        
        # زنجیره خیلی طولانی مشکوک است
        if len(ips) > 5:
            analysis.add_signal(SpoofingSignal(
                type='suspicious_proxy_chain',
                severity='medium',
                confidence=0.6,
                description=f'زنجیره پروکسی بیش از حد طولانی ({len(ips)} hop)',
                evidence={'chain_length': len(ips), 'ips': ips}
            ))
        
        # بررسی وجود IP های نامعتبر در زنجیره
        invalid_ips = [ip for ip in ips if not self._is_valid_ip(ip)]
        if invalid_ips:
            analysis.add_signal(SpoofingSignal(
                type='invalid_ip_in_chain',
                severity='high',
                confidence=0.85,
                description='IP نامعتبر در زنجیره پروکسی',
                evidence={'invalid_ips': invalid_ips}
            ))
        
        # بررسی تکرار IP در زنجیره (حلقه)
        if len(ips) != len(set(ips)):
            analysis.add_signal(SpoofingSignal(
                type='proxy_loop_detected',
                severity='high',
                confidence=0.9,
                description='تکرار IP در زنجیره پروکسی (حلقه احتمالی)',
                evidence={'ips': ips}
            ))
    
    def _check_reserved_ips(
        self, 
        extracted_ips: Dict[str, Optional[str]], 
        analysis: SpoofingAnalysis
    ):
        """بررسی استفاده از IP های رزرو شده"""
        reserved_patterns = [
            '0.0.0.0',
            '255.255.255.255',
            '127.',  # loopback
            '169.254.',  # link-local
        ]
        
        for header, ip in extracted_ips.items():
            if not ip or header == 'REMOTE_ADDR':
                continue
            
            for pattern in reserved_patterns:
                if ip.startswith(pattern):
                    analysis.add_signal(SpoofingSignal(
                        type='reserved_ip_usage',
                        severity='critical',
                        confidence=1.0,
                        description=f'استفاده از IP رزرو شده: {ip}',
                        evidence={'header': header, 'ip': ip, 'pattern': pattern}
                    ))
    
    def _behavioral_analysis(
        self, 
        request, 
        extracted_ips: Dict[str, Optional[str]], 
        analysis: SpoofingAnalysis
    ):
        """تحلیل رفتاری درخواست‌ها"""
        primary_ip = extracted_ips.get('HTTP_X_REAL_IP') or extracted_ips.get('REMOTE_ADDR')
        
        if not primary_ip:
            return
        
        now = datetime.now()
        
        # پاک‌سازی تاریخچه قدیمی (بیش از 1 ساعه)
        cutoff = now - timedelta(hours=1)
        self._request_history[primary_ip] = [
            ts for ts in self._request_history[primary_ip] 
            if ts > cutoff
        ]
        
        # اضافه کردن درخواست فعلی
        self._request_history[primary_ip].append(now)
        
        # بررسی rate غیرعادی
        recent_requests = len(self._request_history[primary_ip])
        
        if recent_requests > 1000:  # بیش از 1000 درخواست در ساعت
            analysis.add_signal(SpoofingSignal(
                type='abnormal_request_rate',
                severity='high',
                confidence=0.8,
                description=f'نرخ درخواست غیرعادی: {recent_requests} req/hour',
                evidence={'requests_per_hour': recent_requests}
            ))
        
        # بررسی تغییر ناگهانی User-Agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        fingerprint = hashlib.md5(user_agent.encode()).hexdigest()
        
        if primary_ip in self._ip_fingerprints:
            if self._ip_fingerprints[primary_ip] != fingerprint:
                analysis.add_signal(SpoofingSignal(
                    type='user_agent_change',
                    severity='medium',
                    confidence=0.5,
                    description='تغییر User-Agent برای همان IP',
                    evidence={
                        'old_fingerprint': self._ip_fingerprints[primary_ip],
                        'new_fingerprint': fingerprint
                    }
                ))
        
        self._ip_fingerprints[primary_ip] = fingerprint
    
    def _geolocation_analysis(
        self, 
        extracted_ips: Dict[str, Optional[str]], 
        analysis: SpoofingAnalysis
    ):
        """مقایسه جغرافیایی IP های مختلف"""
        # این بخش نیاز به سرویس geolocation دارد
        # در صورت تفاوت زیاد در موقعیت جغرافیایی، سیگنال می‌دهد
        
        try:
            from django_iran_ip.core.validators import IPGeolocation
            
            geo = IPGeolocation(timeout=2.0)
            locations = {}
            
            for header, ip in extracted_ips.items():
                if ip and not self._is_private_ip(ip):
                    loc = geo.get_location(ip)
                    if loc and loc.get('country_code'):
                        locations[header] = loc['country_code']
            
            # اگر کشورهای مختلفی گزارش شده
            unique_countries = set(locations.values())
            if len(unique_countries) > 1:
                analysis.add_signal(SpoofingSignal(
                    type='geo_inconsistency',
                    severity='high',
                    confidence=0.75,
                    description='تناقض در موقعیت جغرافیایی IP ها',
                    evidence={'locations': locations}
                ))
        except ImportError:
            logger.debug("Geolocation module not available")
        except Exception as e:
            logger.warning(f"Geolocation analysis failed: {e}")
    
    def _fingerprint_analysis(
        self, 
        request, 
        extracted_ips: Dict[str, Optional[str]], 
        analysis: SpoofingAnalysis
    ):
        """تحلیل fingerprint کامل درخواست"""
        # بررسی هدرهای مشکوک
        suspicious_headers = [
            'HTTP_X_FORWARDED_HOST',
            'HTTP_X_ORIGINAL_URL',
            'HTTP_X_REWRITE_URL',
        ]
        
        found_suspicious = [
            h for h in suspicious_headers 
            if request.META.get(h)
        ]
        
        if found_suspicious:
            analysis.add_signal(SpoofingSignal(
                type='suspicious_headers_present',
                severity='low',
                confidence=0.4,
                description='وجود هدرهای مشکوک',
                evidence={'headers': found_suspicious}
            ))
        
        # بررسی عدم وجود هدرهای معمول
        expected_headers = ['HTTP_USER_AGENT', 'HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE']
        missing_headers = [h for h in expected_headers if not request.META.get(h)]
        
        if len(missing_headers) >= 2:
            analysis.add_signal(SpoofingSignal(
                type='missing_standard_headers',
                severity='medium',
                confidence=0.6,
                description='عدم وجود هدرهای استاندارد',
                evidence={'missing': missing_headers}
            ))
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """بررسی اعتبار IP"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """بررسی IP خصوصی"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
    
    def clear_history(self, ip: Optional[str] = None):
        """پاک‌سازی تاریخچه"""
        if ip:
            self._request_history.pop(ip, None)
            self._ip_fingerprints.pop(ip, None)
        else:
            self._request_history.clear()
            self._ip_fingerprints.clear()


class SpoofingProtectionMiddleware:
    """Middleware برای محافظت خودکار در برابر IP Spoofing"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.detector = IPSpoofingDetector(
            enable_behavioral=True,
            enable_geolocation=False  # برای performance
        )
        
        # خواندن تنظیمات
        from django.conf import settings
        self.auto_block = getattr(settings, 'IRAN_IP_SPOOFING_AUTO_BLOCK', False)
        self.log_only = getattr(settings, 'IRAN_IP_SPOOFING_LOG_ONLY', True)
        self.threshold = getattr(settings, 'IRAN_IP_SPOOFING_THRESHOLD', 70.0)
        
        logger.info(
            f"SpoofingProtection initialized: "
            f"auto_block={self.auto_block}, threshold={self.threshold}"
        )
    
    def __call__(self, request):
        from django.http import HttpResponseForbidden
        
        # استخراج IP ها از هدرهای مختلف
        extracted_ips = self._extract_all_ips(request)
        
        # تحلیل
        analysis = self.detector.analyze(request, extracted_ips)
        
        # اضافه کردن نتایج به request
        request.spoofing_analysis = analysis
        request.is_ip_suspicious = analysis.is_suspicious
        
        # لاگ کردن در صورت مشکوک بودن
        if analysis.is_suspicious:
            logger.warning(
                f"Suspicious IP detected: risk={analysis.risk_score:.2f}, "
                f"signals={[s.type for s in analysis.signals]}, "
                f"ip={extracted_ips.get('REMOTE_ADDR')}"
            )
        
        # مسدود کردن در صورت فعال بودن
        if (not self.log_only and 
            self.auto_block and 
            analysis.risk_score >= self.threshold):
            return HttpResponseForbidden(
                "Access denied: Suspicious request detected"
            )
        
        return self.get_response(request)
    
    def _extract_all_ips(self, request) -> Dict[str, Optional[str]]:
        """استخراج تمام IP ها از هدرهای مختلف"""
        headers = [
            'HTTP_AR_REAL_IP',
            'HTTP_X_REAL_IP',
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_TRUE_CLIENT_IP',
            'REMOTE_ADDR'
        ]
        
        result = {}
        for header in headers:
            value = request.META.get(header)
            if value:
                # برای X-Forwarded-For، اولین IP را بگیر
                if 'FORWARDED' in header:
                    result[header] = value.split(',')[0].strip()
                else:
                    result[header] = value.strip()
        
        return result