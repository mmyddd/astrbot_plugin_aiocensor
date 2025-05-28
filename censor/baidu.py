# data/plugins/astrbot_plugin_aiocensor/censor/baidu.py
import aiohttp
import base64
import json
import asyncio
from typing import Any, Tuple
from datetime import datetime

from ..common import CensorBase, RiskLevel  # type: ignore
from ..common.exceptions import CensorError  # type: ignore


class BaiduAuth:
    """百度内容安全API鉴权"""
    __slots__ = ("_api_key", "_secret_key", "_token", "_last_request_time", "_semaphore")

    def __init__(self, api_key: str, secret_key: str):
        self._api_key = api_key
        self._secret_key = secret_key
        self._token = None
        self._last_request_time = datetime.now()
        # 限制并发请求数为2，避免触发QPS限制
        self._semaphore = asyncio.Semaphore(2)

    async def fetch_token(self) -> str:
        """获取百度API的access token"""
        if self._token:
            return self._token

        token_url = 'https://aip.baidubce.com/oauth/2.0/token'
        params = {
            'grant_type': 'client_credentials',
            'client_id': self._api_key,
            'client_secret': self._secret_key
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(token_url, data=params) as response:
                result = await response.json()

        if 'access_token' in result and 'scope' in result:
            if 'brain_all_scope' not in result['scope'].split(' '):
                raise CensorError('请确保已开通内容安全API权限')
            self._token = result['access_token']
            return self._token
        else:
            raise CensorError('请检查API_KEY和SECRET_KEY是否正确')


class BaiduCensor(CensorBase):
    """百度内容审核"""
    __slots__ = ("_text_url", "_image_url", "_auth", "_session", "_request_interval")

    def __init__(self, config: dict[str, Any]) -> None:
        self._text_url = "https://aip.baidubce.com/rest/2.0/solution/v1/text_censor/v2/user_defined"
        self._image_url = "https://aip.baidubce.com/rest/2.0/solution/v1/img_censor/user_defined"
        self._auth = BaiduAuth(config["api_key"], config["secret_key"])
        self._session = aiohttp.ClientSession()
        # 默认请求间隔200ms，避免触发QPS限制
        self._request_interval = config.get("request_interval", 0.2)

    async def _make_request(self, url: str, payload: dict) -> dict:
        """封装请求逻辑，添加频率控制"""
        async with self._auth._semaphore:
            # 确保请求间隔
            elapsed = (datetime.now() - self._auth._last_request_time).total_seconds()
            if elapsed < self._request_interval:
                await asyncio.sleep(self._request_interval - elapsed)
            
            self._auth._last_request_time = datetime.now()
            token = await self._auth.fetch_token()
            request_url = f"{url}?access_token={token}"
            
            try:
                async with self._session.post(
                    request_url,
                    data=payload,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    result = await response.json()
                    
                    if 'error_code' in result:
                        error_msg = result.get('error_msg', '未知错误')
                        if 'request limit reached' in error_msg:
                            # 遇到限流错误时自动增加间隔时间
                            self._request_interval = min(1.0, self._request_interval * 1.5)
                            await asyncio.sleep(self._request_interval)
                            return await self._make_request(url, payload)
                        raise CensorError(f"百度内容审核请求异常: {error_msg}")
                    
                    # 请求成功时适当减少间隔时间
                    self._request_interval = max(0.1, self._request_interval * 0.9)
                    return result
                    
            except aiohttp.ClientError as e:
                raise CensorError(f"网络请求异常: {str(e)}")

    async def detect_text(self, text: str) -> Tuple[RiskLevel, set[str]]:
        """文本内容审核"""
        payload = {"text": text}
        result = await self._make_request(self._text_url, payload)

        conclusion = result.get("conclusion", {})
        conclusion_type = conclusion.get("type", 1)

        if conclusion_type == 1:
            risk_level = RiskLevel.Pass
        elif conclusion_type == 2:
            risk_level = RiskLevel.Block
        else:
            risk_level = RiskLevel.Review

        risk_words = set()
        for item in result.get("data", []):
            if "hits" in item:
                for hit in item["hits"]:
                    risk_words.update(hit.get("words", []))
            if "msg" in item:
                risk_words.add(item["msg"])

        return risk_level, risk_words

    async def detect_image(self, image: str) -> Tuple[RiskLevel, set[str]]:
        """图片内容审核"""
        if image.startswith("http"):
            payload = {"imgUrl": image}
        else:
            payload = {"image": image.split("base64://")[1] if image.startswith("base64://") else image}

        result = await self._make_request(self._image_url, payload)

        conclusion = result.get("conclusion", {})
        conclusion_type = conclusion.get("type", 1)

        if conclusion_type == 1:
            risk_level = RiskLevel.Pass
        elif conclusion_type == 2:
            risk_level = RiskLevel.Block
        else:
            risk_level = RiskLevel.Review

        risk_words = set()
        for item in result.get("data", []):
            if "msg" in item:
                risk_words.add(item["msg"])
            if "subType" in item:
                risk_words.add(str(item["subType"]))

        return risk_level, risk_words

    async def close(self) -> None:
        """清理资源"""
        await self._session.close()
