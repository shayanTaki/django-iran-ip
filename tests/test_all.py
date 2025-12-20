import unittest
import django
from unittest.mock import Mock, patch, MagicMock
from django.conf import settings
from django.http import HttpResponse, HttpResponseForbidden

# تنظیمات جنگو
if not settings.configured:
    settings.configure(
        DEBUG=True,
        DATABASES={},
        INSTALLED_APPS=['django_iran_ip'],
        CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
        SECRET_KEY='test-key',
    )
    django.setup()

from django_iran_ip.core.strategies import HeaderStrategy, ServiceStrategy
from django_iran_ip.core.resolver import IPResolver
from django_iran_ip.core.validators import IPValidator, IranIPChecker, IPGeolocation
from django_iran_ip.contrib.django.middleware import IranIPMiddleware


class TestCoreComponents(unittest.TestCase):
    def setUp(self):
        self.validator = IPValidator()
        self.checker = IranIPChecker()

    def test_ip_validation_logic(self):
        self.assertTrue(self.validator.is_valid_ipv4("1.1.1.1"))
        self.assertEqual(self.validator.get_ip_type("127.0.0.1"), "loopback")  # حالا پاس می‌شود


class TestStrategies(unittest.TestCase):
    def test_header_strategy_priority(self):
        strategy = HeaderStrategy()
        request = Mock()
        request.META = {
            'HTTP_AR_REAL_IP': '5.22.10.1',
            'REMOTE_ADDR': '127.0.0.1'
        }
        self.assertEqual(strategy.get_ip(request), '5.22.10.1')


class TestMiddleware(unittest.TestCase):
    def setUp(self):
        self.get_response = Mock(return_value=HttpResponse("OK"))

    def test_middleware_attaches_ip(self):
        middleware = IranIPMiddleware(self.get_response)
        request = Mock()
        request.META = {'HTTP_X_REAL_IP': '5.22.10.1'}
        middleware(request)
        self.assertEqual(request.client_ip, '5.22.10.1')

    # اصلاح نحوه پچ کردن برای جلوگیری از ModuleNotFoundError
    def test_middleware_blocking_logic(self):
        with patch('django_iran_ip.contrib.django.middleware.conf') as mock_conf:
            mock_conf.CHECK_IRAN_IP = True
            mock_conf.BLOCK_NON_IRAN_IP = True
            mock_conf.LOG_LEVEL = 'WARNING'

            middleware = IranIPMiddleware(self.get_response)
            request = Mock()
            request.META = {'HTTP_X_REAL_IP': '8.8.8.8'}  # IP غیر ایرانی

            response = middleware(request)
            self.assertIsInstance(response, HttpResponseForbidden)


class TestGeolocation(unittest.TestCase):
    @patch('httpx.Client')
    def test_normalization(self, mock_client):
        geo = IPGeolocation()

        # دیتای تست مطابق با فرمت ipapi.co (اولین سرویس در لیست)
        mock_data = {
            'country_name': 'Iran',
            'country_code': 'IR',
            'city': 'Tehran',
            'org': 'Irancell'
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_data

        mock_context = MagicMock()
        mock_context.__enter__.return_value.get.return_value = mock_response
        mock_client.return_value = mock_context

        result = geo.get_location("5.22.10.1")
        self.assertIsNotNone(result)
        self.assertEqual(result['country_code'], 'IR')


if __name__ == '__main__':
    unittest.main()