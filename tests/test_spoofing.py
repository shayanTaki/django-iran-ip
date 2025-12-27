import unittest
import time
from unittest.mock import Mock, patch
from datetime import datetime

try:
    from django.conf import settings
    if not settings.configured:
        settings.configure(SECRET_KEY='test')
    from django_iran_ip.core.spoofing import IPSpoofingDetector, SpoofingAnalysis, SpoofingSignal
except ImportError:
    import sys
    sys.path.append('src')
    from django_iran_ip.core.spoofing import IPSpoofingDetector, SpoofingAnalysis, SpoofingSignal


class TestSpoofingDetector(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        print("\n" + "="*70)
        print("🚀 Starting IP Spoofing Detection Tests (Fast Mode)")
        print("="*70)
        cls.start_time = time.time()
    
    @classmethod
    def tearDownClass(cls):
        total_time = time.time() - cls.start_time
        print("\n" + "="*70)
        print(f"✅ All tests completed in {total_time:.3f} seconds")
        print("="*70)
    
    def setUp(self):
        self.detector = IPSpoofingDetector(
            enable_behavioral=False, 
            enable_geolocation=False
        )
        self.request = Mock()
        self.request.META = {
            'HTTP_USER_AGENT': 'Mozilla/5.0',
            'HTTP_ACCEPT': 'text/html',
            'HTTP_ACCEPT_LANGUAGE': 'en-US'
        }
    
    def test_01_legitimate_request(self):
        """✅ درخواست معتبر"""
        extracted_ips = {
            'HTTP_X_REAL_IP': '8.8.8.8',
            'HTTP_CF_CONNECTING_IP': '8.8.8.8',
            'REMOTE_ADDR': '8.8.8.8'
        }
        analysis = self.detector.analyze(self.request, extracted_ips)
        self.assertFalse(analysis.is_suspicious)

    def test_02_private_ip_in_cdn_header(self):
        """🚨 IP خصوصی در CDN"""
        extracted_ips = {
            'HTTP_CF_CONNECTING_IP': '192.168.1.1',
            'REMOTE_ADDR': '8.8.8.8'
        }
        analysis = self.detector.analyze(self.request, extracted_ips)
        self.assertTrue(analysis.is_suspicious)
        self.assertTrue(any(s.type == 'private_ip_in_cdn_header' for s in analysis.signals))

    def test_03_header_inconsistency(self):
        """⚠️ تناقض در هدرها"""
        extracted_ips = {
            'HTTP_X_REAL_IP': '1.2.3.4',
            'HTTP_CF_CONNECTING_IP': '5.6.7.8',
            'REMOTE_ADDR': '9.10.11.12'
        }
        analysis = self.detector.analyze(self.request, extracted_ips)
        self.assertTrue(analysis.is_suspicious)

    def test_04_reserved_ip(self):
        """🚨 IP رزرو شده"""
        extracted_ips = {
            'HTTP_X_REAL_IP': '127.0.0.1',
            'REMOTE_ADDR': '8.8.8.8'
        }
        analysis = self.detector.analyze(self.request, extracted_ips)
        self.assertTrue(analysis.is_suspicious)

    def test_05_long_proxy_chain(self):
        """⚠️ زنجیره پروکسی طولانی"""
        long_chain = ', '.join([f'1.2.3.{i}' for i in range(10)])
        self.request.META['HTTP_X_FORWARDED_FOR'] = long_chain
        
        extracted_ips = {'REMOTE_ADDR': '8.8.8.8'}
        analysis = self.detector.analyze(self.request, extracted_ips)
        self.assertTrue(any(s.type == 'suspicious_proxy_chain' for s in analysis.signals))

    def test_06_invalid_ip_in_chain(self):
        """🚨 IP نامعتبر در زنجیره"""
        self.request.META['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, invalid-ip, 5.6.7.8'
        extracted_ips = {'REMOTE_ADDR': '8.8.8.8'}
        analysis = self.detector.analyze(self.request, extracted_ips)
        self.assertTrue(any(s.type == 'invalid_ip_in_chain' for s in analysis.signals))

    def test_07_proxy_loop(self):
        """🚨 حلقه در پروکسی"""
        self.request.META['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, 5.6.7.8, 1.2.3.4'
        extracted_ips = {'REMOTE_ADDR': '8.8.8.8'}
        analysis = self.detector.analyze(self.request, extracted_ips)
        self.assertTrue(any(s.type == 'proxy_loop_detected' for s in analysis.signals))

    def test_08_missing_headers(self):
        """⚠️ نبود هدرهای استاندارد"""
        self.request.META = {'REMOTE_ADDR': '8.8.8.8'} # بدون User-Agent
        extracted_ips = {'REMOTE_ADDR': '8.8.8.8'}
        analysis = self.detector.analyze(self.request, extracted_ips)
        self.assertTrue(any(s.type == 'missing_standard_headers' for s in analysis.signals))

    def test_09_behavioral_rate_limit_optimized(self):
        detector = IPSpoofingDetector(enable_behavioral=True)
        target_ip = '8.8.8.8'
        
        detector._request_history[target_ip] = [datetime.now()] * 1005
        
        self.request.META['REMOTE_ADDR'] = target_ip
        extracted_ips = {'REMOTE_ADDR': target_ip}
        
        analysis = detector.analyze(self.request, extracted_ips)
        
        self.assertTrue(any(s.type == 'abnormal_request_rate' for s in analysis.signals))

    def test_10_risk_score_calculation(self):
        """📊 محاسبه Risk Score"""
        analysis = SpoofingAnalysis(is_suspicious=False, risk_score=0.0)
        analysis.add_signal(SpoofingSignal('test', 'critical', 1.0, 'Test'))
        self.assertEqual(analysis.risk_score, 100.0)
        self.assertEqual(analysis.recommended_action, "block")

    def test_11_multiple_vulnerabilities(self):
        """🚨 ترکیب چند آسیب‌پذیری"""
        self.request.META['HTTP_X_FORWARDED_FOR'] = '127.0.0.1, 192.168.1.1'
        extracted_ips = {
            'HTTP_CF_CONNECTING_IP': '192.168.1.1',
            'HTTP_X_REAL_IP': '127.0.0.1',
            'REMOTE_ADDR': '8.8.8.8'
        }
        analysis = self.detector.analyze(self.request, extracted_ips)
        self.assertGreater(analysis.risk_score, 80.0)

if __name__ == '__main__':
    unittest.main()