from django.http import HttpResponseForbidden
from django.core.cache import cache
from django_iran_ip.core.resolver import IPResolver
from django_iran_ip.core.validators import IPValidator, IranIPChecker, IPGeolocation
from django_iran_ip.conf import conf
import logging

logger = logging.getLogger('django_iran_ip')


class IranIPMiddleware:


    def __init__(self, get_response):
        self.get_response = get_response


        logger.setLevel(getattr(logging, conf.LOG_LEVEL, logging.WARNING))


        self.resolver = IPResolver(enable_cache=conf.ENABLE_CACHE)


        self.iran_checker = None
        if conf.CHECK_IRAN_IP:
            self.iran_checker = IranIPChecker()


        self.geolocation = None
        if conf.ENABLE_GEOLOCATION:
            self.geolocation = IPGeolocation(timeout=conf.REQUEST_TIMEOUT)

        logger.info("IranIPMiddleware initialized")

    def __call__(self, request):

        client_ip = self.resolver.get_client_ip(request)


        request.client_ip = client_ip


        if client_ip:

            if conf.VALIDATE_IP:
                validator = IPValidator()
                request.client_ip_valid = validator.is_valid_ipv4(client_ip)
                request.client_ip_type = validator.get_ip_type(client_ip)


            if conf.CHECK_IRAN_IP and self.iran_checker:
                request.is_iran_ip = self.iran_checker.is_iran_ip(client_ip)


                if conf.BLOCK_NON_IRAN_IP and not request.is_iran_ip:
                    logger.warning(f"Non-Iran IP blocked: {client_ip}")
                    return HttpResponseForbidden("Access denied: Only Iran IPs are allowed")


            if conf.ENABLE_GEOLOCATION and self.geolocation:

                cache_key = f"iran_ip_geo_{client_ip}"
                geo_info = cache.get(cache_key)

                if not geo_info:
                    geo_info = self.geolocation.get_location(client_ip)
                    if geo_info:

                        cache.set(cache_key, geo_info, 86400)

                request.client_geo = geo_info

            logger.debug(f"Client IP detected: {client_ip}")
        else:
            request.client_ip_valid = False
            request.client_ip_type = "unknown"
            request.is_iran_ip = False
            request.client_geo = None
            logger.warning("No client IP detected")

        response = self.get_response(request)


        if client_ip and hasattr(settings := __import__('django.conf').conf.settings, 'IRAN_IP_ADD_HEADER'):
            if getattr(settings, 'IRAN_IP_ADD_HEADER', False):
                response['X-Client-IP'] = client_ip

        return response


class IranIPLoggingMiddleware:


    def __init__(self, get_response):
        self.get_response = get_response
        self.resolver = IPResolver(enable_cache=conf.ENABLE_CACHE)
        logger.info("IranIPLoggingMiddleware initialized")

    def __call__(self, request):
        client_ip = self.resolver.get_client_ip(request)

        if client_ip:
            logger.info(
                f"IP: {client_ip} | "
                f"Path: {request.path} | "
                f"Method: {request.method} | "
                f"User-Agent: {request.META.get('HTTP_USER_AGENT', 'Unknown')}"
            )

        return self.get_response(request)


class IranIPRateLimitMiddleware:


    def __init__(self, get_response):
        self.get_response = get_response
        self.resolver = IPResolver(enable_cache=conf.ENABLE_CACHE)


        self.rate_limit = getattr(
            __import__('django.conf').conf.settings,
            'IRAN_IP_RATE_LIMIT',
            100  # پیش‌فرض: 100 درخواست
        )
        self.rate_period = getattr(
            __import__('django.conf').conf.settings,
            'IRAN_IP_RATE_PERIOD',
            3600  # پیش‌فرض: 1 ساعت
        )

        logger.info(
            f"IranIPRateLimitMiddleware initialized: "
            f"{self.rate_limit} requests per {self.rate_period}s"
        )

    def __call__(self, request):
        client_ip = self.resolver.get_client_ip(request)

        if client_ip:
            cache_key = f"iran_ip_rate_{client_ip}"
            requests = cache.get(cache_key, 0)

            if requests >= self.rate_limit:
                logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                return HttpResponseForbidden("Rate limit exceeded")

            # افزایش تعداد درخواست‌ها
            cache.set(cache_key, requests + 1, self.rate_period)

        return self.get_response(request)