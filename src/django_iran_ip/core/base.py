from abc import ABC, abstractmethod
from typing import Optional, Any

class BaseIPStrategy(ABC):


    @abstractmethod
    def get_ip(self, request: Optional[Any] = None) -> Optional[str]:

        pass

    def __repr__(self):
        return f"<{self.__class__.__name__}>"