from typing import Optional, List, Dict
from .base import BaseIPStrategy
from .strategies import HeaderStrategy, ServiceStrategy, CachedServiceStrategy
import logging

logger = logging.getLogger(__name__)


class IPResolver:
    
    
    def __init__(
        self, 
        strategies: Optional[List[BaseIPStrategy]] = None, 
        enable_cache: bool = True,
        enable_spoofing_detection: bool = False
    ):
        
        if strategies:
            self.strategies = strategies
        else:
            # اولویت با هدر است چون هزینه‌ای ندارد، اگر نشد سراغ API می‌رود
            header_strategy = HeaderStrategy()
            
            if enable_cache:
                service_strategy = CachedServiceStrategy(
                    base_strategy=ServiceStrategy(use_iran_services=True),
                    cache_duration=3600  # 1 ساعت
                )
            else:
                service_strategy = ServiceStrategy(use_iran_services=True)
            
            self.strategies = [header_strategy, service_strategy]
        
        # تشخیص IP Spoofing
        self.enable_spoofing_detection = enable_spoofing_detection
        self.spoofing_detector = None
        
        if enable_spoofing_detection:
            try:
                from .spoofing import IPSpoofingDetector
                self.spoofing_detector = IPSpoofingDetector(
                    enable_behavioral=True,
                    enable_geolocation=False  # می‌توان از تنظیمات خواند
                )
                logger.info("IP Spoofing detection enabled")
            except ImportError:
                logger.warning("Spoofing detection module not available")
                self.enable_spoofing_detection = False
    
    def get_client_ip(self, request=None) -> Optional[str]:
        
        for strategy in self.strategies:
            try:
                ip = strategy.get_ip(request)
                if ip:
                    logger.debug(f"IP found using {strategy.__class__.__name__}: {ip}")
                    
                    # اگر تشخیص spoofing فعال است، بررسی شود
                    if self.enable_spoofing_detection and request:
                        is_safe = self._verify_ip_safety(request, ip)
                        if not is_safe:
                            logger.warning(f"IP {ip} marked as suspicious, continuing search...")
                            continue
                    
                    return ip
            except Exception as e:
                logger.warning(f"Error in {strategy.__class__.__name__}: {str(e)}")
                continue
        
        logger.warning("No IP address found using any strategy")
        return None
    
    def get_client_info(self, request=None) -> Dict[str, any]:
        
        result = {
            'ip': None,
            'strategy_used': None,
            'is_valid': False,
            'spoofing_analysis': None
        }
        
        for strategy in self.strategies:
            try:
                ip = strategy.get_ip(request)
                if ip:
                    result['ip'] = ip
                    result['strategy_used'] = strategy.__class__.__name__
                    result['is_valid'] = self._is_valid_ip(ip)
                    
                    # تحلیل spoofing
                    if self.enable_spoofing_detection and request:
                        result['spoofing_analysis'] = self._analyze_spoofing(request, ip)
                    
                    return result
            except Exception as e:
                logger.warning(f"Error in {strategy.__class__.__name__}: {str(e)}")
                continue
        
        return result
    
    def _verify_ip_safety(self, request, ip: str) -> bool:
       
        if not self.spoofing_detector:
            return True
        
        # استخراج همه IP ها
        extracted_ips = self._extract_all_ips(request)
        
        # تحلیل
        analysis = self.spoofing_detector.analyze(request, extracted_ips)
        
        # اگر خطر بالا باشد، IP را قبول نکن
        return analysis.risk_score < 70.0
    
    def _analyze_spoofing(self, request, ip: str) -> Optional[Dict]:
        """تحلیل کامل spoofing برای IP"""
        if not self.spoofing_detector:
            return None
        
        extracted_ips = self._extract_all_ips(request)
        analysis = self.spoofing_detector.analyze(request, extracted_ips)
        
        return {
            'is_suspicious': analysis.is_suspicious,
            'risk_score': analysis.risk_score,
            'recommended_action': analysis.recommended_action,
            'signals_count': len(analysis.signals),
            'signals': [
                {
                    'type': s.type,
                    'severity': s.severity,
                    'confidence': s.confidence,
                    'description': s.description
                }
                for s in analysis.signals
            ]
        }
    
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
                if 'FORWARDED' in header:
                    result[header] = value.split(',')[0].strip()
                else:
                    result[header] = value.strip()
        
        return result
    
    def _is_valid_ip(self, ip: str) -> bool:
        """بررسی اعتبار IP address"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False