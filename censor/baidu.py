# data/plugins/astrbot_plugin_aiocensor/censor/baidu.py
import aiohttp
import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Tuple, Optional, Union, Dict

from ..common import RiskLevel
from ..common.exceptions import CensorError, APILimitError, AuthError


class BaiduResponseParser:
    """百度API响应解析器"""
    
    @staticmethod
    def parse(response_text: str) -> Dict[str, Any]:
        try:
            return json.loads(response_text) if response_text else {}
        except json.JSONDecodeError:
            raise CensorError(f"无效的JSON响应: {response_text[:200]}")

    @staticmethod
    def validate_response(result: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(result, dict):
            raise CensorError(f"API返回了非字典响应: {type(result)}")
        return result

    @staticmethod
    def extract_conclusion(result: Dict[str, Any]) -> Dict[str, Any]:
        conclusion = result.get("conclusion", {})
        if isinstance(conclusion, str):
            try:
                return json.loads(conclusion)
            except:
                return {"type": 4, "msg": conclusion}
        return conclusion if isinstance(conclusion, dict) else {}

    @staticmethod
    def extract_data(result: Dict[str, Any]) -> list:
        data = result.get("data", [])
        return data if isinstance(data, list) else []


class BaiduAuth:
    """百度内容安全API鉴权"""
    __slots__ = ("_api_key", "_secret_key", "_token", "_token_expiry", "_semaphore")

    def __init__(self, api_key: str, secret_key: str):
        self._api_key = api_key
        self._secret_key = secret_key
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self._semaphore = asyncio.Semaphore(1)

    async def fetch_token(self) -> str:
        """获取并缓存access token"""
        if self._token and self._token_expiry and datetime.now() < self._token_expiry:
            return self._token

        async with self._semaphore:
            # 双重检查锁定
            if self._token and self._token_expiry and datetime.now() < self._token_expiry:
                return self._token

            token_url = 'https://aip.baidubce.com/oauth/2.0/token'
            params = {
                'grant_type': 'client_credentials',
                'client_id': self._api_key,
                'client_secret': self._secret_key
            }

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(token_url, data=params) as response:
                        response_text = await response.text()
                        result = BaiduResponseParser.validate_response(
                            BaiduResponseParser.parse(response_text)
                        )

                        if 'access_token' in result and 'expires_in' in result:
                            expires_in = int(result['expires_in'])
                            self._token = result['access_token']
                            # 修复类型错误：确保timedelta只与datetime相加
                            self._token_expiry = datetime.now() + timedelta(seconds=expires_in) - timedelta(minutes=5)
                            return self._token
                        raise AuthError(f"获取token失败: {result.get('error_description', '未知错误')}")
            except Exception as e:
                raise AuthError(f"获取token异常: {str(e)}")


class BaiduCensor:
    """百度内容审核（生产级稳定版）"""
    __slots__ = ("_text_url", "_image_url", "_auth", "_session", "_request_interval")

    def __init__(self, config: dict[str, Any]) -> None:
        self._text_url = "https://aip.baidubce.com/rest/2.0/solution/v1/text_censor/v2/user_defined"
        self._image_url = "https://aip.baidubce.com/rest/2.0/solution/v1/img_censor/user_defined"
        self._auth = BaiduAuth(config["api_key"], config["secret_key"])
        self._session = aiohttp.ClientSession()
        self._request_interval = max(1.0, float(config.get("request_interval", 1.0)))

    async def _make_request(self, url: str, payload: dict) -> dict:
        """执行API请求"""
        try:
            await asyncio.sleep(self._request_interval)
            token = await self._auth.fetch_token()
            
            async with self._session.post(
                f"{url}?access_token={token}",
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                response_text = await response.text()
                result = BaiduResponseParser.validate_response(
                    BaiduResponseParser.parse(response_text)
                )

                if 'error_code' in result or 'error_msg' in result:
                    error_msg = result.get('error_msg', '未知错误')
                    if 'limit' in error_msg.lower():
                        self._request_interval = min(5.0, self._request_interval * 1.5)
                        raise APILimitError(f"API限流: {error_msg}")
                    raise CensorError(f"API错误: {error_msg}")
                
                return result
        except APILimitError:
            raise
        except Exception as e:
            raise CensorError(f"请求失败: {str(e)}")

    async def _process_result(self, result: dict) -> Tuple[RiskLevel, set[str]]:
        """处理API结果"""
        conclusion = BaiduResponseParser.extract_conclusion(result)
        data = BaiduResponseParser.extract_data(result)

        risk_level = {
            1: RiskLevel.Pass,
            2: RiskLevel.Block,
            3: RiskLevel.Review,
            4: RiskLevel.Review
        }.get(int(conclusion.get("type", 4)), RiskLevel.Review)

        risk_words = set()
        for item in data:
            if not isinstance(item, dict):
                continue
                
            for field in ["msg", "subType", "label", "hint"]:
                if isinstance(item.get(field), str):
                    risk_words.add(item[field])
            
            for hit in item.get("hits", []):
                if isinstance(hit, dict):
                    risk_words.update(w for w in hit.get("words", []) if isinstance(w, str))

        return risk_level, risk_words

    async def detect_text(self, text: str) -> Tuple[RiskLevel, set[str]]:
        """文本内容审核"""
        try:
            if not isinstance(text, str):
                raise CensorError("输入文本必须是字符串")
            result = await self._make_request(self._text_url, {"text": text})
            return await self._process_result(result)
        except APILimitError:
            raise
        except Exception as e:
            raise CensorError(f"文本审核失败: {str(e)}")

    async def detect_image(self, image: str) -> Tuple[RiskLevel, set[str]]:
        """图片内容审核"""
        try:
            if not isinstance(image, str):
                raise CensorError("图片输入必须是字符串")
            
            payload = (
                {"imgUrl": image} if image.startswith("http") else
                {"image": image[9:] if image.startswith("base64://") else image}
            )
            result = await self._make_request(self._image_url, payload)
            return await self._process_result(result)
        except APILimitError:
            raise
        except Exception as e:
            raise CensorError(f"图片审核失败: {str(e)}")

    async def close(self) -> None:
        """清理资源"""
        await self._session.close()
