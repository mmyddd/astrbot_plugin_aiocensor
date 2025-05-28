import asyncio
import base64
import json
from typing import Any

import aiohttp

from ..common.interfaces import CensorBase  # type: ignore
from ..common.types import CensorError, RiskLevel  # type: ignore
from ..common.utils import censor_retry  # type: ignore


class BaiduAuth:
    """百度内容安全API鉴权"""

    __slots__ = ("_api_key", "_secret_key", "_token")

    def __init__(self, api_key: str, secret_key: str):
        self._api_key = api_key
        self._secret_key = secret_key
        self._token = None

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

    __slots__ = ("_text_url", "_image_url", "_auth", "_session", "_semaphore")

    def __init__(self, config: dict[str, Any]) -> None:
        self._text_url = "https://aip.baidubce.com/rest/2.0/solution/v1/text_censor/v2/user_defined"
        self._image_url = "https://aip.baidubce.com/rest/2.0/solution/v1/img_censor/user_defined"
        self._auth = BaiduAuth(config["api_key"], config["secret_key"])
        self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15))
        self._semaphore = asyncio.Semaphore(80)

    async def __aenter__(self) -> "BaiduCensor":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        await self._session.close()

    @censor_retry(max_retries=3)
    async def _check_single_text(self, text: str) -> tuple[RiskLevel, set[str]]:
        """对单段文本进行内容审核"""
        token = await self._auth.fetch_token()
        url = f"{self._text_url}?access_token={token}"
        payload = {"text": text}

        async with self._semaphore:
            async with self._session.post(
                url, 
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            ) as response:
                response.raise_for_status()
                result = await response.json()

                if 'error_code' in result:
                    raise CensorError(f"内容审核请求异常: {result.get('error_msg')}")

                risk_words_set: set[str] = set()
                conclusion = result.get("conclusion", "")
                conclusion_type = conclusion.get("type", 1)  # 1:合规，2:不合规，3:疑似，4:审核失败

                if conclusion_type == 1:
                    risk_level = RiskLevel.Pass
                elif conclusion_type == 2:
                    risk_level = RiskLevel.Block
                else:
                    risk_level = RiskLevel.Review

                # 收集风险词
                for item in result.get("data", []):
                    if "hits" in item:
                        for hit in item["hits"]:
                            risk_words_set.update(hit.get("words", []))

                return risk_level, risk_words_set

    async def detect_text(self, text: str) -> tuple[RiskLevel, set[str]]:
        """对文本进行内容审核"""
        try:
            if not text:
                return RiskLevel.Pass, set()

            return await self._check_single_text(text)

        except Exception as e:
            raise CensorError(f"内容审核过程中发生异常: {e!s}")

    @censor_retry(max_retries=3)
    async def detect_image(self, image: str) -> tuple[RiskLevel, set[str]]:  # type: ignore
        """对图片进行内容审核"""
        token = await self._auth.fetch_token()
        url = f"{self._image_url}?access_token={token}"

        if image.startswith("base64://"):
            image_content = image[9:]
            payload = {"image": image_content}
        elif image.startswith("http"):
            payload = {"imgUrl": image}
        else:
            raise CensorError("预期外的输入")

        async with self._semaphore:
            async with self._session.post(
                url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            ) as response:
                response.raise_for_status()
                result = await response.json()

                if 'error_code' in result:
                    raise CensorError(f"内容审核请求异常: {result.get('error_msg')}")

                reason_words_set: set[str] = set()
                conclusion = result.get("conclusion", {})
                conclusion_type = conclusion.get("type", 1)  # 1:合规，2:不合规，3:疑似，4:审核失败

                if conclusion_type == 1:
                    risk_level = RiskLevel.Pass
                elif conclusion_type == 2:
                    risk_level = RiskLevel.Block
                else:
                    risk_level = RiskLevel.Review

                # 收集风险描述
                for item in result.get("data", []):
                    if "msg" in item:
                        reason_words_set.add(item["msg"])
                    if "subType" in item:
                        reason_words_set.add(str(item["subType"]))

                return risk_level, reason_words_set
