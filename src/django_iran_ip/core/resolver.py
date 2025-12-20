from typing import Optional, List, Dict
from .base import BaseIPStrategy
from .strategies import HeaderStrategy, ServiceStrategy, CachedServiceStrategy
import logging

logger = logging.getLogger(__name__)


class IPResolver:


    def __init__(self, strategies: Optional[List[BaseIPStrategy]] = None, enable_cache: bool = True):

        if strategies:
            self.strategies = strategies
        else:

            header_strategy = HeaderStrategy()

            if enable_cache:
                service_strategy = CachedServiceStrategy(
                    base_strategy=ServiceStrategy(use_iran_services=True),
                    cache_duration=3600
                )
            else:
                service_strategy = ServiceStrategy(use_iran_services=True)

            self.strategies = [header_strategy, service_strategy]

    def get_client_ip(self, request=None) -> Optional[str]:

        for strategy in self.strategies:
            try:
                ip = strategy.get_ip(request)
                if ip:
                    logger.debug(f"IP found using {strategy.__class__.__name__}: {ip}")
                    return ip
            except Exception as e:
                logger.warning(f"Error in {strategy.__class__.__name__}: {str(e)}")
                continue

        logger.warning("No IP address found using any strategy")
        return None

    def get_client_info(self, request=None) -> Dict[str, Optional[str]]:

        for strategy in self.strategies:
            try:
                ip = strategy.get_ip(request)
                if ip:
                    return {
                        'ip': ip,
                        'strategy_used': strategy.__class__.__name__,
                        'is_valid': self._is_valid_ip(ip)
                    }
            except Exception as e:
                logger.warning(f"Error in {strategy.__class__.__name__}: {str(e)}")
                continue

        return {
            'ip': None,
            'strategy_used': None,
            'is_valid': False
        }

    def _is_valid_ip(self, ip: str) -> bool:

        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False