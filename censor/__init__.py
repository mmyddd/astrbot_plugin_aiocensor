# data/plugins/astrbot_plugin_aiocensor/censor/__init__.py
from .aliyun import AliyunCensor
from .llm import LLMCensor
from .local import LocalCensor
from .tencent import TencentCensor
from .baidu import BaiduCensor

# 确保所有Censor类都继承自CensorBase
__all__ = [
    "AliyunCensor",
    "LLMCensor", 
    "LocalCensor",
    "TencentCensor",
    "BaiduCensor"
]

# 类型提示支持
try:
    from typing import TYPE_CHECKING
    if TYPE_CHECKING:
        from .aliyun import AliyunCensor as _AliyunCensor
        from .llm import LLMCensor as _LLMCensor
        from .local import LocalCensor as _LocalCensor
        from .tencent import TencentCensor as _TencentCensor
        from .baidu import BaiduCensor as _BaiduCensor
        
        __all__ += [
            "_AliyunCensor",
            "_LLMCensor",
            "_LocalCensor",
            "_TencentCensor",
            "_BaiduCensor"
        ]
except ImportError:
    pass
