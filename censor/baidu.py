import aiohttp
import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Tuple, Optional, Dict, List, Set
import logging

from ..common import RiskLevel
from ..common.exceptions import CensorError, APILimitError, AuthError

logger = logging.getLogger(__name__)

class BaiduResponseParser:
    """增强版响应解析器，彻底解决set()问题"""
    
    @staticmethod
    def parse(response_text: str) -> Dict[str, Any]:
        try:
            data = json.loads(response_text) if response_text else {}
            if not isinstance(data, dict):
                raise ValueError("API响应格式错误，预期字典类型")
            return data
        except json.JSONDecodeError as e:
            logger.error(f"JSON解析失败: {str(e)} 原始响应: {response_text[:200]}")
            raise CensorError("API返回了无效的JSON数据")

    @staticmethod
    def normalize_conclusion(conclusion: Any) -> Dict[str, Any]:
        """标准化conclusion字段，处理各种异常情况"""
        if isinstance(conclusion, dict):
            return conclusion
        if isinstance(conclusion, str):
            try:
                if conclusion.strip() in ("set()", "set([])", "set"):
                    return {"type": 4, "msg": "无效内容"}
                return json.loads(conclusion)
            except json.JSONDecodeError:
                return {"type": 4, "msg": conclusion}
        return {"type": 4, "msg": "未知内容类型"}

    @staticmethod
    def clean_risk_word(word: Any) -> Optional[str]:
        """清洗单个风险词"""
        if not word:
            return None
        word = str(word).strip()
        if word.lower() in ("set()", "set([])", "set", "none", "null"):
            return None
        return word if len(word) < 100 else word[:100] + "..."

    @staticmethod
    def extract_risk_data(data: List[Dict]) -> Set[str]:
        """从API数据中提取有效风险词"""
        risk_words = set()
        
        for item in data:
            if not isinstance(item, dict):
                continue
                
            # 处理直接字段
            for field in ["msg", "label", "subType", "hint", "reason"]:
                if field in item:
                    if word := BaiduResponseParser.clean_risk_word(item[field]):
                        risk_words.add(word)
            
            # 处理嵌套hits结构
            hits = item.get("hits", [])
            if isinstance(hits, list):
                for hit in hits:
                    if isinstance(hit, dict):
                        words = hit.get("words", [])
                        if isinstance(words, list):
                            for w in words:
                                if word := BaiduResponseParser.clean_risk_word(w):
                                    risk_words.add(word)
        
        return risk_words

class BaiduAuth:
    """带自动刷新的Token管理器"""
    
    def __init__(self, api_key: str, secret_key: str):
        self._api_key = api_key
        self._secret_key = secret_key
        self._token = None
        self._expires_at = None
        self._lock = asyncio.Lock()

    async def get_token(self) -> str:
        """获取有效token，自动刷新"""
        async with self._lock:
            if self._token and self._expires_at and datetime.now() < self._expires_at:
                return self._token
                
            token_url = "https://aip.baidubce.com/oauth/2.0/token"
            params = {
                "grant_type": "client_credentials",
                "client_id": self._api_key,
                "client_secret": self._secret_key
            }

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(token_url, data=params) as resp:
                        data = await resp.json(content_type=None)
                        
                        if not isinstance(data, dict):
                            raise AuthError("Token响应格式错误")
                            
                        if "access_token" not in data or "expires_in" not in data:
                            raise AuthError(data.get("error_description", "获取token失败"))
                            
                        self._token = data["access_token"]
                        self._expires_at = datetime.now() + timedelta(
                            seconds=int(data["expires_in"]) - 300  # 提前5分钟过期
                        )
                        return self._token
                        
            except Exception as e:
                logger.error(f"获取Token失败: {str(e)}")
                raise AuthError(f"认证服务不可用: {str(e)}")

class BaiduCensor:
    """生产级百度内容审核实现"""
    
    def __init__(self, config: Dict[str, Any]):
        self._text_url = "https://aip.baidubce.com/rest/2.0/solution/v1/text_censor/v2/user_defined"
        self._image_url = "https://aip.baidubce.com/rest/2.0/solution/v1/img_censor/user_defined"
        self._auth = BaiduAuth(config["api_key"], config["secret_key"])
        self._session = aiohttp.ClientSession()
        self._min_interval = max(1.0, float(config.get("request_interval", 1.0)))
        self._last_request_time = None

    async def _rate_limited_request(self, url: str, payload: Dict) -> Dict:
        """带速率限制的API请求"""
        now = datetime.now()
        if self._last_request_time:
            elapsed = (now - self._last_request_time).total_seconds()
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
        
        try:
            token = await self._auth.get_token()
            self._last_request_time = datetime.now()
            
            async with self._session.post(
                f"{url}?access_token={token}",
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                response_text = await resp.text()
                result = BaiduResponseParser.parse(response_text)
                
                if "error_code" in result:
                    error_msg = result.get("error_msg", "")
                    if any(kw in error_msg.lower() for kw in ["limit", "quota", "qps"]):
                        self._min_interval = min(5.0, self._min_interval * 1.5)
                        raise APILimitError(f"请求受限: {error_msg}")
                    raise CensorError(f"API错误: {error_msg}")
                
                return result
                
        except APILimitError:
            raise
        except Exception as e:
            logger.error(f"API请求异常: {str(e)}")
            raise CensorError(f"服务暂时不可用: {str(e)}")

    async def detect_text(self, text: str) -> Tuple[RiskLevel, Set[str]]:
        """文本内容审核（完全修复set问题）"""
        try:
            if not isinstance(text, str) or not text.strip():
                return RiskLevel.Pass, set()
                
            result = await self._rate_limited_request(
                self._text_url,
                {"text": text}
            )
            
            conclusion = BaiduResponseParser.normalize_conclusion(
                result.get("conclusion", {})
            )
            
            risk_level = {
                1: RiskLevel.Pass,
                2: RiskLevel.Block,
                3: RiskLevel.Review,
                4: RiskLevel.Review
            }.get(int(conclusion.get("type", 4)), RiskLevel.Review)
            
            risk_words = BaiduResponseParser.extract_risk_data(
                result.get("data", [])
            )
            
            return risk_level, risk_words
            
        except Exception as e:
            logger.error(f"文本审核失败: {str(e)}")
            return RiskLevel.Review, {f"处理错误: {str(e)}"}

    async def detect_image(self, image: str) -> Tuple[RiskLevel, Set[str]]:
        """图片内容审核"""
        try:
            if not isinstance(image, str) or not image.strip():
                return RiskLevel.Pass, set()
                
            payload = (
                {"imgUrl": image} if image.startswith("http") else
                {"image": image[9:] if image.startswith("base64://") else image}
            )
            
            result = await self._rate_limited_request(
                self._image_url,
                payload
            )
            
            conclusion = BaiduResponseParser.normalize_conclusion(
                result.get("conclusion", {})
            )
            
            risk_level = {
                1: RiskLevel.Pass,
                2: RiskLevel.Block,
                3: RiskLevel.Review,
                4: RiskLevel.Review
            }.get(int(conclusion.get("type", 4)), RiskLevel.Review)
            
            risk_words = BaiduResponseParser.extract_risk_data(
                result.get("data", [])
            )
            
            return risk_level, risk_words
            
        except Exception as e:
            logger.error(f"图片审核失败: {str(e)}")
            return RiskLevel.Review, {f"处理错误: {str(e)}"}

    async def close(self):
        await self._session.close()
