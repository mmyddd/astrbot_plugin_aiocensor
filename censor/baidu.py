# data/plugins/astrbot_plugin_aiocensor/censor/baidu.py
import aiohttp
import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Tuple, Optional

from ..common import RiskLevel
from ..common.exceptions import CensorError, APILimitError, AuthError


class BaiduAuth:
    """百度内容安全API鉴权"""
    __slots__ = ("_api_key", "_secret_key", "_token", "_token_expiry", "_semaphore")

    def __init__(self, api_key: str, secret_key: str):
        self._api_key = api_key
        self._secret_key = secret_key
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self._semaphore = asyncio.Semaphore(1)  # 严格单线程访问

    async def fetch_token(self) -> str:
        """获取并缓存access token"""
        if self._token and self._token_expiry and datetime.now() < self._token_expiry:
            return self._token

        async with self._semaphore:
            # 双重检查锁定模式
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
                        result = json.loads(response_text) if response_text else {}

                        if not isinstance(result, dict):
                            raise AuthError(f"无效的token响应: {response_text}")

                        if 'access_token' in result and 'expires_in' in result:
                            self._token = result['access_token']
                            # 提前5分钟过期以避免边缘情况
                            self._token_expiry = datetime.now() + timedelta(seconds=int(result['expires_in'])) - timedelta(minutes=5)
                            
                            if 'brain_all_scope' not in result.get('scope', '').split(' '):
                                raise AuthError('缺少必要权限: brain_all_scope')
                            return self._token
                        else:
                            raise AuthError(f"获取token失败: {result.get('error_description', '未知错误')}")
            except json.JSONDecodeError:
                raise AuthError(f"token响应不是有效的JSON: {response_text}")
            except Exception as e:
                raise AuthError(f"获取token时发生异常: {str(e)}")


class BaiduCensor:
    """百度内容审核（增强版）"""
    __slots__ = ("_text_url", "_image_url", "_auth", "_session", "_request_interval", 
                "_retry_count", "_last_fail_time")

    def __init__(self, config: dict[str, Any]) -> None:
        self._text_url = "https://aip.baidubce.com/rest/2.0/solution/v1/text_censor/v2/user_defined"
        self._image_url = "https://aip.baidubce.com/rest/2.0/solution/v1/img_censor/user_defined"
        self._auth = BaiduAuth(config["api_key"], config["secret_key"])
        self._session = aiohttp.ClientSession()
        self._request_interval = max(1.0, float(config.get("request_interval", 1.0)))  # 默认1秒间隔
        self._retry_count = 0
        self._last_fail_time: Optional[datetime] = None

    async def _make_request(self, url: str, payload: dict) -> dict:
        """增强的请求处理，带自动退避机制"""
        try:
            # 自动退避逻辑
            if self._last_fail_time:
                elapsed = (datetime.now() - self._last_fail_time).total_seconds()
                backoff_time = min(10.0, 0.5 * (2 ** self._retry_count))  # 指数退避，最大10秒
                if elapsed < backoff_time:
                    await asyncio.sleep(backoff_time - elapsed)

            token = await self._auth.fetch_token()
            request_url = f"{url}?access_token={token}"

            async with self._session.post(
                request_url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                response_text = await response.text()
                
                # 手动处理JSON解析
                try:
                    result = json.loads(response_text) if response_text else {}
                except json.JSONDecodeError:
                    result = {"error_msg": f"无效的JSON响应: {response_text[:200]}"}

                # 错误处理
                if not isinstance(result, dict):
                    raise CensorError(f"API返回了非字典响应: {type(result)}")

                if 'error_code' in result or 'error_msg' in result:
                    error_msg = result.get('error_msg', '未知错误')
                    error_code = result.get('error_code', 'UNKNOWN')
                    
                    if 'request limit reached' in error_msg.lower() or error_code in ('18', '19'):
                        self._retry_count += 1
                        self._last_fail_time = datetime.now()
                        raise APILimitError(f"API请求限制[{error_code}]: {error_msg}")
                    
                    raise CensorError(f"API错误[{error_code}]: {error_msg}")

                # 请求成功时重置计数器
                self._retry_count = 0
                return result

        except APILimitError:
            raise  # 直接抛出限流错误
        except aiohttp.ClientError as e:
            raise CensorError(f"网络请求异常: {str(e)}")
        except Exception as e:
            raise CensorError(f"请求处理异常: {str(e)}")

    async def _safe_detect(self, url: str, payload: dict) -> Tuple[RiskLevel, set[str]]:
        """安全的检测方法，处理响应解析"""
        try:
            result = await self._make_request(url, payload)
            
            # 确保响应结构正确
            if not isinstance(result, dict):
                raise CensorError(f"无效的API响应: {type(result)}")

            conclusion = result.get("conclusion", {})
            if not isinstance(conclusion, dict):
                raise CensorError(f"无效的conclusion字段: {type(conclusion)}")

            conclusion_type = int(conclusion.get("type", 1))
            risk_level = {
                1: RiskLevel.Pass,
                2: RiskLevel.Block,
                3: RiskLevel.Review,
                4: RiskLevel.Review
            }.get(conclusion_type, RiskLevel.Review)

            risk_words = set()
            data = result.get("data", [])
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        if "hits" in item and isinstance(item["hits"], list):
                            for hit in item["hits"]:
                                if isinstance(hit, dict):
                                    words = hit.get("words", [])
                                    if isinstance(words, list):
                                        risk_words.update(w for w in words if isinstance(w, str))
                        if "msg" in item and isinstance(item["msg"], str):
                            risk_words.add(item["msg"])
                        if "subType" in item:
                            risk_words.add(str(item["subType"]))

            return risk_level, risk_words

        except APILimitError:
            raise
        except Exception as e:
            raise CensorError(f"解析响应失败: {str(e)}")

    async def detect_text(self, text: str) -> Tuple[RiskLevel, set[str]]:
        """文本内容审核"""
        try:
            if not isinstance(text, str):
                raise CensorError("输入必须是字符串")
            return await self._safe_detect(self._text_url, {"text": text})
        except APILimitError:
            raise
        except Exception as e:
            raise CensorError(f"文本审核失败: {str(e)}")

    async def detect_image(self, image: str) -> Tuple[RiskLevel, set[str]]:
        """图片内容审核"""
        try:
            if not isinstance(image, str):
                raise CensorError("图片输入必须是字符串")
            
            if image.startswith("http"):
                payload = {"imgUrl": image}
            else:
                payload = {"image": image.split("base64://")[1] if image.startswith("base64://") else image}
            
            return await self._safe_detect(self._image_url, payload)
        except APILimitError:
            raise
        except Exception as e:
            raise CensorError(f"图片审核失败: {str(e)}")

    async def close(self) -> None:
        """清理资源"""
        await self._session.close()
