# data/plugins/astrbot_plugin_aiocensor/common/exceptions.py
class CensorError(Exception):
    """内容审核异常基类"""
    pass

class APILimitError(CensorError):
    """API请求限制异常"""
    pass

class AuthError(CensorError):
    """认证异常"""
    pass
