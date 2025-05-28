import asyncio
import hashlib
from typing import Any, Dict, Optional
from datetime import datetime, timedelta
import logging

from .common import CensorBase, CensorResult, Message, RiskLevel
from .db import DBManager

logger = logging.getLogger(__name__)

class CensorFlow:
    """修复重复记录问题的审核流程控制器"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.text_censor = self._init_censor(config.get("text_censor_provider"))
        self.image_censor = self._init_censor(config.get("image_censor_provider")) 
        self.db_mgr = DBManager(config.get("db_path", "censor.db"))
        self._cache = {}  # 简单内存缓存，生产环境应替换为Redis
        self._cache_lock = asyncio.Lock()
        self._pending_requests = set()

    def _init_censor(self, provider: str) -> Optional[CensorBase]:
        # ...初始化各审核器的原有逻辑...
        pass

    async def _get_cache(self, key: str) -> Optional[CensorResult]:
        """线程安全的缓存获取"""
        async with self._cache_lock:
            if entry := self._cache.get(key):
                if datetime.now() < entry["expire_time"]:
                    return entry["result"]
                del self._cache[key]
            return None

    async def _set_cache(self, key: str, result: CensorResult, ttl: int = 300):
        """线程安全的缓存设置"""
        async with self._cache_lock:
            self._cache[key] = {
                "result": result,
                "expire_time": datetime.now() + timedelta(seconds=ttl)
            }

    def _generate_fingerprint(self, content: str, content_type: str) -> str:
        """生成内容指纹防止重复"""
        return hashlib.md5(
            f"{content_type}:{content}".encode("utf-8")
        ).hexdigest()

    async def submit_text(
        self, 
        content: str,
        source: str,
        extra: Optional[Dict[str, Any]] = None
    ) -> CensorResult:
        """修复后的文本审核提交"""
        if not self.text_censor:
            raise RuntimeError("文本审核器未初始化")

        msg = Message(content, source)
        fp = self._generate_fingerprint(content, "text")
        
        # 检查是否正在处理相同请求
        if fp in self._pending_requests:
            return CensorResult(msg, RiskLevel.Review, {"重复请求"})
            
        self._pending_requests.add(fp)
        try:
            # 检查缓存
            if cached := await self._get_cache(fp):
                return cached

            # 执行审核
            risk_level, risk_words = await self.text_censor.detect_text(content)
            
            # 创建结果对象
            result = CensorResult(
                message=msg,
                risk_level=risk_level,
                risk_words=risk_words,
                extra=extra or {}
            )

            # 缓存结果
            await self._set_cache(fp, result)
            
            # 记录日志（确保只记录一次）
            if risk_level != RiskLevel.Pass and self.config.get("enable_audit_log", True):
                if not self.db_mgr.has_recent_log(fp, minutes=5):
                    self.db_mgr.add_audit_log(
                        content=content,
                        content_type="text",
                        risk_level=risk_level.value,
                        risk_words=",".join(risk_words),
                        fingerprint=fp,
                        extra=extra
                    )
            
            return result
            
        except Exception as e:
            logger.error(f"文本审核失败: {str(e)}")
            return CensorResult(msg, RiskLevel.Review, {str(e)})
        finally:
            self._pending_requests.discard(fp)

    async def submit_image(
        self,
        image: str,
        source: str
    ) -> CensorResult:
        """修复后的图片审核提交"""
        if not self.image_censor:
            raise RuntimeError("图片审核器未初始化")

        msg = Message(image, source)
        fp = self._generate_fingerprint(image, "image")
        
        if fp in self._pending_requests:
            return CensorResult(msg, RiskLevel.Review, {"重复请求"})
            
        self._pending_requests.add(fp)
        try:
            if cached := await self._get_cache(fp):
                return cached

            risk_level, risk_words = await self.image_censor.detect_image(image)
            
            result = CensorResult(
                message=msg,
                risk_level=risk_level,
                risk_words=risk_words,
                extra={"source": source}
            )
            
            await self._set_cache(fp, result)
            
            if risk_level != RiskLevel.Pass and self.config.get("enable_audit_log", True):
                if not self.db_mgr.has_recent_log(fp, minutes=5):
                    self.db_mgr.add_audit_log(
                        content=image[:1000],  # 限制长度
                        content_type="image",
                        risk_level=risk_level.value,
                        risk_words=",".join(risk_words),
                        fingerprint=fp,
                        extra={"source": source}
                    )
            
            return result
            
        except Exception as e:
            logger.error(f"图片审核失败: {str(e)}")
            return CensorResult(msg, RiskLevel.Review, {str(e)})
        finally:
            self._pending_requests.discard(fp)

    async def close(self):
        """清理资源"""
        if self.text_censor:
            await self.text_censor.close()
        if self.image_censor:
            await self.image_censor.close()
        await self.db_mgr.close()
