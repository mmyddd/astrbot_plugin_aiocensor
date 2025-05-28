class CensorError(Exception):
    """基础审核异常"""
    pass

class APILimitError(CensorError):
    """API限制异常"""
    pass

class AuthError(CensorError):
    """认证异常"""
    pass

class InvalidFormatError(CensorError):
    """无效数据格式异常"""
    pass
