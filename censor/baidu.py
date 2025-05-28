import aiohttp
import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Tuple, Optional, Dict, List

from ..common import RiskLevel
from ..common.exceptions import CensorError, APILimitError, AuthError

class BaiduResponseParser:
    """增强版响应解析器"""
    
    @staticmethod
    def parse(response_text: str) -> Dict[str, Any]:
        try:
            data = json.loads(response_text) if response_text else {}
            if not isinstance(data, dict):
                raise ValueError("Response is not a dictionary")
            return data
        except json.JSONDecodeError as e:
            raise CensorError(f"Invalid JSON: {str(e)}")

    @staticmethod
    def normalize_conclusion(conclusion: Any) -> Dict[str, Any]:
        """标准化conclusion字段"""
        if isinstance(conclusion, dict):
            return conclusion
        elif isinstance(conclusion, str):
            try:
                return json.loads(conclusion)
            except:
                return {"type": 4, "msg": conclusion}
        return {"type": 4, "msg": "Invalid conclusion format"}

    @staticmethod
    def extract_risk_words(items: List[Dict]) -> List[str]:
        """安全提取风险词"""
        words = []
        for item in items:
            if not isinstance(item, dict):
                continue
                
            # 处理直接字段
            for field in ["msg", "label", "subType", "hint"]:
                if isinstance(item.get(field), str):
                    words.append(item[field])
            
            # 处理嵌套hits结构
            hits = item.get("hits", [])
            if isinstance(hits, list):
                for hit in hits:
                    if isinstance(hit, dict):
                        for w in hit.get("words", []):
                            if isinstance(w, str) and w != "set()":
                                words.append(w)
        return words

class BaiduAuth:
    """修复token管理的鉴权类"""
    
    def __init__(self, api_key: str, secret_key: str):
        self._api_key = api_key
        self._secret_key = secret_key
        self._token = None
        self._token_expiry = None
        self._lock = asyncio.Lock()

    async def fetch_token(self) -> str:
        async with self._lock:
            if self._token and self._token_expiry and datetime.now() < self._token_expiry:
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
                            raise AuthError("Invalid token response format")
                        
                        if "access_token" in data and "expires_in" in data:
                            self._token = data["access_token"]
                            expires_in = int(data["expires_in"])
                            self._token_expiry = datetime.now() + timedelta(seconds=expires_in)
                            return self._token
                        raise AuthError(data.get("error_description", "Unknown error"))
            except Exception as e:
                raise AuthError(f"Token fetch failed: {str(e)}")

class BaiduCensor:
    """最终稳定版内容审核"""
    
    def __init__(self, config: Dict[str, Any]):
        self._text_url = "https://aip.baidubce.com/rest/2.0/solution/v1/text_censor/v2/user_defined"
        self._image_url = "https://aip.baidubce.com/rest/2.0/solution/v1/img_censor/user_defined"
        self._auth = BaiduAuth(config["api_key"], config["secret_key"])
        self._session = aiohttp.ClientSession()
        self._min_interval = max(1.0, float(config.get("request_interval", 1.0)))
        self._last_request = None

    async def _safe_request(self, url: str, payload: Dict) -> Dict:
        """带速率限制的安全请求"""
        if self._last_request:
            elapsed = (datetime.now() - self._last_request).total_seconds()
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
        
        try:
            token = await self._auth.fetch_token()
            self._last_request = datetime.now()
            
            async with self._session.post(
                f"{url}?access_token={token}",
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                response_text = await resp.text()
                result = BaiduResponseParser.parse(response_text)
                
                if "error_code" in result:
                    err_msg = result.get("error_msg", "")
                    if "limit" in err_msg.lower():
                        self._min_interval = min(5.0, self._min_interval * 1.5)
                        raise APILimitError(err_msg)
                    raise CensorError(err_msg)
                
                return result
        except Exception as e:
            raise CensorError(f"API request failed: {str(e)}")

    async def detect_text(self, text: str) -> Tuple[RiskLevel, List[str]]:
        """文本审核（修复set()问题）"""
        try:
            result = await self._safe_request(self._text_url, {"text": text})
            conclusion = BaiduResponseParser.normalize_conclusion(result.get("conclusion", {}))
            
            risk_level = {
                1: RiskLevel.Pass,
                2: RiskLevel.Block,
                3: RiskLevel.Review,
                4: RiskLevel.Review
            }.get(int(conclusion.get("type", 4)), RiskLevel.Review)
            
            risk_words = BaiduResponseParser.extract_risk_words(
                result.get("data", [])
            )
            
            return risk_level, risk_words
        except Exception as e:
            raise CensorError(f"Text detection failed: {str(e)}")

    async def detect_image(self, image: str) -> Tuple[RiskLevel, List[str]]:
        """图片审核"""
        try:
            payload = (
                {"imgUrl": image} if image.startswith("http") else
                {"image": image[9:] if image.startswith("base64://") else image}
            )
            result = await self._safe_request(self._image_url, payload)
            conclusion = BaiduResponseParser.normalize_conclusion(result.get("conclusion", {}))
            
            risk_level = {
                1: RiskLevel.Pass,
                2: RiskLevel.Block,
                3: RiskLevel.Review,
                4: RiskLevel.Review
            }.get(int(conclusion.get("type", 4)), RiskLevel.Review)
            
            risk_words = BaiduResponseParser.extract_risk_words(
                result.get("data", [])
            )
            
            return risk_level, risk_words
        except Exception as e:
            raise CensorError(f"Image detection failed: {str(e)}")

    async def close(self):
        await self._session.close()
