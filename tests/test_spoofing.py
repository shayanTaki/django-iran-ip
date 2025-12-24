import unittest
from unittest.mock import Mock, patch
from datetime import datetime
from django_iran_ip.core.spoofing import (
    IPSpoofingDetector,
    SpoofingSignal,
    SpoofingAnalysis
)


class TestSpoofingAnalysis(unittest.TestCase):
    """تست‌های کلاس SpoofingAnalysis"""
    
    def test_initial_state(self):
        """تست وضعیت اولیه"""
        analysis = SpoofingAnalysis(is_suspicious=False, risk_score=0.0)
        self.assertFalse(analysis.is_suspicious)
        self.assertEqual(analysis.risk_score, 0.0)
        self.assertEqual(len(analysis.signals), 0)
        self.assertEqual(analysis.recommended_action, "allow")
    
    def test_add_low_severity_signal(self):
        """تست اضافه کردن سیگنال با شدت پایین"""
        analysis = SpoofingAnalysis(is_suspicious=False, risk_score=0.0)
        signal = SpoofingSignal(
            type='test',
            severity='low',
            confidence=1.0,
            description='Test signal'
        )
        analysis.add_signal(signal)
        
        self.assertEqual(len(analysis.signals), 1)
        self.assertEqual(analysis.risk_score, 10.0)
        self.assertFalse(analysis.is_suspicious)
        self.assertEqual(analysis.recommended_action, "allow")
    
    def test_add_critical_signal(self):
        """تست اضافه کردن سیگنال بحرانی"""
        analysis = SpoofingAnalysis(is_suspicious=False, risk_score=0.0)
        signal = SpoofingSignal(
            type='critical_issue',
            severity='critical',
            confidence=1.0,
            description='Critical spoofing detected'
        )
        analysis.add_signal(signal)
        
        self.assertTrue(analysis.is_suspicious)
        self.assertEqual(analysis.risk_score, 100.0)
        self.assertEqual(analysis.recommended_action, "block")
    
    def test_multiple_signals_accumulate(self):
        """تست تجمیع چند سیگنال"""
        analysis = SpoofingAnalysis(is_suspicious=False, risk_score=0.0)
        
        # اضافه کردن 3 سیگنال متوسط
        for i in range(3):
            signal = SpoofingSignal(
                type=f'signal_{i}',
                severity='medium',
                confidence=0.8,
                description=f'Signal {i}'
            )
            analysis.add_signal(signal)
        
        # 3 * 25 * 0.8 = 60
        self.assertEqual(analysis.risk_score, 60.0)
        self.assertTrue(analysis.is_suspicious)
        self.assertEqual(analysis.recommended_action, "challenge")


class TestIPSpoofingDetector(unittest.TestCase):
    """تست‌های کلاس IPSpoofingDetector"""
    
    def setUp(self):
        self.detector = IPSpoofingDetector(
            enable_behavioral=False,
            enable_geolocation=False
        )
        self.request = Mock()
        self.request.META = {}
    
    def test_header_inconsistency_detection(self):
        """تست تشخیص تناقض در هدرها"""
        extracted_ips = {
            'HTTP_X_REAL_IP': '1.2.3.4',
            'HTTP_CF_CONNECTING_IP': '5.6.7.8',
            'REMOTE_ADDR': '9.10.11.12'
        }
        
        analysis = self.detector.analyze(self.request, extracted_ips)
        
        # باید سیگنال تناقض داشته باشد
        inconsistency_signals = [
            s for s in analysis.signals 
            if s.type == 'header_inconsistency'
        ]
        self.assertTrue(len(inconsistency_signals) > 0)
    
    def test_private_ip_in_cdn_header(self):
        """تست تشخیص IP خصوصی در هدر CDN"""
        extracted_ips = {
            'HTTP_CF_CONNECTING_IP': '192.168.1.1',  # Private IP!
            'REMOTE_ADDR': '8.8.8.8'
        }
        
        analysis = self.detector.analyze(self.request, extracted_ips)
        
        # باید سیگنال critical داشته باشد
        private_ip_signals = [
            s for s in analysis.signals 
            if s.type == 'private_ip_in_cdn_header'
        ]
        self.assertTrue(len(private_ip_signals) > 0)
        self.assertEqual(private_ip_signals[0].severity, 'critical')
    
    def test_suspicious_proxy_chain(self):
        """تست تشخیص زنجیره پروکسی مشکوک"""
        # زنجیره خیلی طولانی
        long_chain = ', '.join([f'1.2.3.{i}' for i in range(10)])
        self.request.META = {'HTTP_X_FORWARDED_FOR': long_chain}
        
        extracted_ips = {'REMOTE_ADDR': '8.8.8.8'}
        
        analysis = self.detector.analyze(self.request, extracted_ips)
        
        # باید سیگنال زنجیره مشکوک داشته باشد
        proxy_signals = [
            s for s in analysis.signals 
            if s.type == 'suspicious_proxy_chain'
        ]
        self.assertTrue(len(proxy_signals) > 0)
    
    def test_invalid_ip_in_chain(self):
        """تست تشخیص IP نامعتبر در زنجیره"""
        self.request.META = {
            'HTTP_X_FORWARDED_FOR': '1.2.3.4, not-an-ip, 5.6.7.8'
        }
        
        extracted_ips = {'REMOTE_ADDR': '8.8.8.8'}
        
        analysis = self.detector.analyze(self.request, extracted_ips)
        
        # باید سیگنال IP نامعتبر داشته باشد
        invalid_signals = [
            s for s in analysis.signals 
            if s.type == 'invalid_ip_in_chain'
        ]
        self.assertTrue(len(invalid_signals) > 0)
        self.assertEqual(invalid_signals[0].severity, 'high')
    
    def test_proxy_loop_detection(self):
        """تست تشخیص حلقه در زنجیره پروکسی"""
        self.request.META = {
            'HTTP_X_FORWARDED_FOR': '1.2.3.4, 5.6.7.8, 1.2.3.4'  # تکرار!
        }
        
        extracted_ips = {'REMOTE_ADDR': '8.8.8.8'}
        
        analysis = self.detector.analyze(self.request, extracted_ips)
        
        # باید سیگنال حلقه داشته باشد
        loop_signals = [
            s for s in analysis.signals 
            if s.type == 'proxy_loop_detected'
        ]
        self.assertTrue(len(loop_signals) > 0)
    
    def test_reserved_ip_usage(self):
        """تست تشخیص استفاده از IP های رزرو شده"""
        extracted_ips = {
            'HTTP_X_REAL_IP': '127.0.0.1',  # Loopback!
            'REMOTE_ADDR': '8.8.8.8'
        }
        
        analysis = self.detector.analyze(self.request, extracted_ips)
        
        # باید سیگنال IP رزرو شده داشته باشد
        reserved_signals = [
            s for s in analysis.signals 
            if s.type == 'reserved_ip_usage'
        ]
        self.assertTrue(len(reserved_signals) > 0)
        self.assertEqual(reserved_signals[0].severity, 'critical')
    
    def test_missing_standard_headers(self):
        """تست تشخیص نبود هدرهای استاندارد"""
        # هیچ User-Agent و Accept نداریم
        self.request.META = {'REMOTE_ADDR': '8.8.8.8'}
        
        extracted_ips = {'REMOTE_ADDR': '8.8.8.8'}
        
        analysis = self.detector.analyze(self.request, extracted_ips)
        
        # باید سیگنال هدرهای گمشده داشته باشد
        missing_signals = [
            s for s in analysis.signals 
            if s.type == 'missing_standard_headers'
        ]
        self.assertTrue(len(missing_signals) > 0)
    
    def test_legitimate_request(self):
        """تست درخواست معتبر بدون مشکل"""
        self.request.META = {
            'HTTP_USER_AGENT': 'Mozilla/5.0',
            'HTTP_ACCEPT': 'text/html',
            'HTTP_ACCEPT_LANGUAGE': 'en-US',
            'REMOTE_ADDR': '8.8.8.8'
        }
        
        extracted_ips = {
            'HTTP_X_REAL_IP': '8.8.8.8',
            'REMOTE_ADDR': '8.8.8.8'
        }
        
        analysis = self.detector.analyze(self.request, extracted_ips)
        
        # نباید سیگنال خاصی داشته باشد
        self.assertEqual(len(analysis.signals), 0)
        self.assertFalse(analysis.is_suspicious)
        self.assertEqual(analysis.recommended_action, "allow")
    
    def test_behavioral_analysis(self):
        """تست تحلیل رفتاری"""
        detector = IPSpoofingDetector(enable_behavioral=True)
        
        self.request.META = {
            'HTTP_USER_AGENT': 'Test Agent',
            'REMOTE_ADDR': '8.8.8.8'
        }
        
        extracted_ips = {'REMOTE_ADDR': '8.8.8.8'}
        
        # ارسال 1500 درخواست
        for _ in range(1500):
            analysis = detector.analyze(self.request, extracted_ips)
        
        # باید سیگنال rate غیرعادی داشته باشد
        rate_signals = [
            s for s in analysis.signals 
            if s.type == 'abnormal_request_rate'
        ]
        self.assertTrue(len(rate_signals) > 0)
    
    def test_user_agent_change(self):
        """تست تشخیص تغییر User-Agent"""
        detector = IPSpoofingDetector(enable_behavioral=True)
        
        # درخواست اول
        self.request.META = {
            'HTTP_USER_AGENT': 'Mozilla/5.0',
            'REMOTE_ADDR': '8.8.8.8'
        }
        extracted_ips = {'REMOTE_ADDR': '8.8.8.8'}
        detector.analyze(self.request, extracted_ips)
        
        # درخواست دوم با User-Agent متفاوت
        self.request.META['HTTP_USER_AGENT'] = 'Chrome/90.0'
        analysis = detector.analyze(self.request, extracted_ips)
        
        # باید سیگنال تغییر User-Agent داشته باشد
        ua_signals = [
            s for s in analysis.signals 
            if s.type == 'user_agent_change'
        ]
        self.assertTrue(len(ua_signals) > 0)
    
    def test_clear_history(self):
        """تست پاک‌سازی تاریخچه"""
        detector = IPSpoofingDetector(enable_behavioral=True)
        
        self.request.META = {'REMOTE_ADDR': '8.8.8.8'}
        extracted_ips = {'REMOTE_ADDR': '8.8.8.8'}
        
        # ایجاد تاریخچه
        detector.analyze(self.request, extracted_ips)
        self.assertTrue('8.8.8.8' in detector._request_history)
        
        # پاک‌سازی
        detector.clear_history('8.8.8.8')
        self.assertFalse('8.8.8.8' in detector._request_history)
    
    def test_multiple_attack_vectors(self):
        """تست ترکیب چند نوع حمله"""
        self.request.META = {
            'HTTP_X_FORWARDED_FOR': '192.168.1.1, 10.0.0.1, 127.0.0.1',  # Private IPs
            'REMOTE_ADDR': '8.8.8.8'
        }
        
        extracted_ips = {
            'HTTP_CF_CONNECTING_IP': '192.168.1.1',  # Private in CDN
            'HTTP_X_REAL_IP': '127.0.0.1',  # Reserved
            'REMOTE_ADDR': '8.8.8.8'
        }
        
        analysis = self.detector.analyze(self.request, extracted_ips)
        
        # باید چند سیگنال مختلف داشته باشد
        self.assertTrue(len(analysis.signals) >= 2)
        self.assertTrue(analysis.is_suspicious)
        self.assertTrue(analysis.risk_score > 50.0)


class TestSpoofingProtectionMiddleware(unittest.TestCase):
    """تست‌های Middleware محافظت از Spoofing"""
    
    @patch('django_iran_ip.core.spoofing.settings')
    def test_middleware_initialization(self, mock_settings):
        """تست راه‌اندازی Middleware"""
        from django_iran_ip.core.spoofing import SpoofingProtectionMiddleware
        
        mock_settings.IRAN_IP_SPOOFING_AUTO_BLOCK = False
        mock_settings.IRAN_IP_SPOOFING_LOG_ONLY = True
        mock_settings.IRAN_IP_SPOOFING_THRESHOLD = 70.0
        
        get_response = Mock()
        middleware = SpoofingProtectionMiddleware(get_response)
        
        self.assertIsNotNone(middleware.detector)
        self.assertFalse(middleware.auto_block)
        self.assertTrue(middleware.log_only)
    
    @patch('django_iran_ip.core.spoofing.settings')
    def test_middleware_allows_safe_request(self, mock_settings):
        """تست اینکه درخواست امن اجازه داده می‌شود"""
        from django_iran_ip.core.spoofing import SpoofingProtectionMiddleware
        
        mock_settings.IRAN_IP_SPOOFING_AUTO_BLOCK = True
        mock_settings.IRAN_IP_SPOOFING_LOG_ONLY = False
        mock_settings.IRAN_IP_SPOOFING_THRESHOLD = 70.0
        
        get_response = Mock(return_value="OK")
        middleware = SpoofingProtectionMiddleware(get_response)
        
        request = Mock()
        request.META = {
            'HTTP_USER_AGENT': 'Mozilla/5.0',
            'HTTP_ACCEPT': 'text/html',
            'REMOTE_ADDR': '8.8.8.8'
        }
        
        response = middleware(request)
        
        self.assertEqual(response, "OK")
        self.assertFalse(request.is_ip_suspicious)


if __name__ == '__main__':
    unittest.main()