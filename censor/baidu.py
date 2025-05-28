import aiohttp
import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Tuple, Set, Dict
import logging

from ..common import RiskLevel
from ..common.exceptions import CensorError, APILimitError, AuthError

logger = logging.getLogger(__name__)

class BaiduResponseCleaner:
    """专门处理百度API响应清洗"""
    
    @staticmethod
    def clean_response(response: Any) -> Dict[str, Any]:
        """清洗API响应数据"""
        if isinstance(response, str):
            try:
                response = json.loads(response)
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON response: {response[:200]}...")
                return {"conclusion": {"type": 4}, "data": []}
        
        if not isinstance(response, dict):
            return {"conclusion": {"type": 4}, "data": []}
            
        return response

    @staticmethod
    def clean_risk_words(raw_data: Any) -> Set[str]:
        """清洗风险词集合"""
        clean_words = set()
        
        if isinstance(raw_data, str):
            if raw_data.strip() not in ("set()", "set([])"):
                clean_words.add(raw_data.strip())
        elif isinstance(raw_data, (list, set)):
            for item in raw_data:
                if isinstance(item, str) and item.strip() not in ("set()", "set([])"):
                    clean_words.add(item.strip())
                elif isinstance(item, dict):
                    for value in item.values():
                        clean_words.update(BaiduResponseCleaner.clean_risk_words(value))
        
        return clean_words

class BaiduCensor(CensorBase):
    """兼容原有接口的百度内容审核（修复set问题）"""
    
    def __init__(self, config: Dict[str, Any]):
        self._api_key = config["api_key"]
        self._secret_key = config["secret_key"]
        self._text_url = "https://aip.baidubce.com/rest/2.0/solution/v1/text_censor/v2/user_defined"
        self._image_url = "https://aip.baidubce.com/rest/2.0/solution/v1/img_censor/user_defined"
        self._session = aiohttp.ClientSession()
        self._token = None
        self._token_expiry = None
        self._request_interval = max(1.0, float(config.get("request_interval", 1.0)))
        self._last_request_time = None

    async def _get_token(self) -> str:
        """获取访问令牌（带自动刷新）"""
        now = datetime.now()
        if self._token and self._token_expiry and now < self._token_expiry:
            return self._token
            
        token_url = "https://aip.baidubce.com/oauth/2.0/token"
        params = {
            "grant_type": "client_credentials",
            "client_id": self._api_key,
            "client_secret": self._secret_key
        }
        
        try:
            async with self._session.post(token_url, data=params) as resp:
                response = await resp.json()
                if "access_token" not in response:
                    raise AuthError(response.get("error_description", "获取token失败"))
                
                self._token = response["access_token"]
                self._token_expiry = now + timedelta(seconds=int(response["expires_in"]) - 300)
                return self._token
        except Exception as e:
            raise AuthError(f"Token获取失败: {str(e)}")

    async def _rate_limited_request(self, url: str, payload: Dict[str, str]) -> Dict[str, Any]:
        """带速率限制的API请求"""
        now = datetime.now()
        if self._last_request_time:
            elapsed = (now - self._last_request_time).total_seconds()
            if elapsed < self._request_interval:
                await asyncio.sleep(self._request_interval - elapsed)
        
        try:
            token = await self._get_token()
            self._last_request_time = datetime.now()
            
            async with self._session.post(
                f"{url}?access_token={token}",
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                response_text = await resp.text()
                cleaned_response = BaiduResponseCleaner.clean_response(response_text)
                
                if "error_code" in cleaned_response:
                    error_msg = cleaned_response.get("error_msg", "")
                    if "limit" in error_msg.lower():
                        self._request_interval = min(5.0, self._request_interval * 1.5)
                        raise APILimitError(error_msg)
                    raise CensorError(error_msg)
                    
                return cleaned_response
                
        except APILimitError:
            raise
        except Exception as e:
            raise CensorError(f"请求失败: {str(e)}")

    async def detect_text(self, text: str) -> Tuple[RiskLevel, Set[str]]:
        """文本审核（自动处理set问题）"""
        try:
            result = await self._rate_limited_request(
                self._text_url,
                {"text": text}
            )
            
            conclusion = result.get("conclusion", {})
            risk_level = {
                1: RiskLevel.Pass,
                2: RiskLevel.Block,
                3: RiskLevel.Review,
                4: RiskLevel.Review
            }.get(int(conclusion.get("type", 4)), RiskLevel.Review)
            
            risk_words = BaiduResponseCleaner.clean_risk_words(result.get("data", []))
            return risk_level, risk_words
            
        except Exception as e:
            logger.error(f"文本审核失败: {str(e)}")
            return RiskLevel.Review, {str(e)}

    async def detect_image(self, image: str) -> Tuple[RiskLevel, Set[str]]:
        """图片审核（自动处理set问题）"""
        try:
            payload = (
                {"imgUrl": image} if image.startswith("http") else
                {"image": image[9:] if image.startswith("base64://") else image}
            )
            
            result = await self._rate_limited_request(
                self._image_url,
                payload
            )
            
            conclusion = result.get("conclusion", {})
            risk_level = {
                1: RiskLevel.Pass,
                2: RiskLevel.Block,
                3: RiskLevel.Review,
                4: RiskLevel.Review
            }.get(int(conclusion.get("type", 4)), RiskLevel.Review)
            
            risk_words = BaiduResponseCleaner.clean_risk_words(result.get("data", []))
            return risk_level, risk_words
            
        except Exception as e:
            logger.error(f"图片审核失败: {str(e)}")
            return RiskLevel.Review, {str(e)}

    async def close(self):
        """清理资源"""
        await self._session.close()
