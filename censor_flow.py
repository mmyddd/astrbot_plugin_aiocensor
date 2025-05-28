import base64
import os
from contextlib import AbstractAsyncContextManager
from typing import Any

import aiohttp

from astrbot.api import AstrBotConfig, logger

from .censor import AliyunCensor, LLMCensor, LocalCensor, TencentCensor, BaiduCensor  # type: ignore
from .common import (  # type: ignore
    CensorBase,
    CensorResult,
    Message,
    RiskLevel,
    get_image_format,
)


class CensorFlow(AbstractAsyncContextManager):
    __slots__ = (
        "_text_censor",
        "_image_censor",
        "_userid_censor",
        "_config",
        "_baidu_censor",
    )

    def __init__(self, config: AstrBotConfig) -> None:
        """
        初始化 CensorFlow 实例

        参数:
            config: AstrBotConfig 实例，包含审核相关的配置信息
        """
        self._config = config

        # 获取文本和图片审核的提供商配置
        text_provider = config.get("text_censor_provider", "")
        image_provider = config.get("image_censor_provider", "")
        enable_image_censor = config.get("enable_image_censor", False)

        # 定义不同审核提供商的配置字典
        configs: dict[str, dict[str, Any]] = {
            "aliyun": {
                "key_id": config.get("aliyun", {}).get("key_id"),
                "key_secret": config.get("aliyun", {}).get("key_secret"),
            },
            "llm": {
                "model": config.get("llm", {}).get("model"),
                "base_url": config.get("llm", {}).get("base_url"),
                "api_key": config.get("llm", {}).get("api_key"),
            },
            "tencent": {
                "secret_id": config.get("tencent", {}).get("secret_id"),
                "secret_key": config.get("tencent", {}).get("secret_key"),
            },
            "local": {"use_logic": True},
            "baidu": {
                "api_key": config.get("baidu", {}).get("api_key"),
                "secret_key": config.get("baidu", {}).get("secret_key"),
            },
        }

        # 初始化文本审核器
        self._text_censor = self._create_censor(text_provider, configs)

        # 根据配置决定是否初始化图片审核器
        self._image_censor = None
        if enable_image_censor and image_provider:
            self._image_censor = self._create_censor(image_provider, configs)

        # 初始化用户ID审核器
        self._userid_censor = LocalCensor({"use_logic": False})

        # 初始化百度内容安全审核器（如果配置了百度API）
        self._baidu_censor = None
        if config.get("baidu", {}).get("api_key") and config.get("baidu", {}).get("secret_key"):
            self._baidu_censor = BaiduCensor(configs["baidu"])

    def _create_censor(
        self, provider: str, configs: dict[str, dict[str, Any]]
    ) -> CensorBase | None:
        """初始化一个Censor实例

        参数:
            provider: 审核提供商的名称
            configs: 包含各提供商配置的字典

        返回:
            CensorBase实例或None
        """
        if not provider:
            return None

        try:
            if provider == "Aliyun":
                return AliyunCensor(configs["aliyun"])
            elif provider == "LLM":
                return LLMCensor(configs["llm"])
            elif provider == "Tencent":
                return TencentCensor(configs["tencent"])
            elif provider == "Local":
                logger.debug(configs["local"])
                return LocalCensor(configs["local"])
            elif provider == "Baidu":
                return BaiduCensor(configs["baidu"])
            else:
                logger.error(f"未知的审核提供商: {provider}")
                return None
        except Exception as e:
            logger.error(f"初始化审核提供商 '{provider}' 时出错: {e}")
            return None

    @property
    def text_censor(self) -> CensorBase:
        """返回文本审核实例"""
        return self._text_censor

    @property
    def image_censor(self) -> CensorBase | None:
        """返回图片审核实例"""
        return self._image_censor

    @property
    def userid_censor(self) -> LocalCensor:
        """返回用户ID审核实例"""
        return self._userid_censor

    async def __aenter__(self) -> "CensorFlow":
        # 异步上下文管理器的进入方法
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        # 异步上下文管理器的退出方法，调用清理资源
        await self.close()

    async def submit_text(
        self,
        content: str,
        source: str,
        extra: dict[str, Any] | None = None,
    ) -> CensorResult:
        """
        提交文本审核任务

        参数:
            content: 待审核的文本内容
            source: 文本来源
            extra: 可选的额外信息字典

        返回:
            CensorResult: 审核结果对象
        """
        if not self._text_censor:
            raise RuntimeError("文本审核器未成功初始化，请检查配置")

        msg = Message(content, source)
        try:
            # 优先使用百度审核（如果配置）
            if self._baidu_censor:
                risk, reasons = await self._baidu_censor.detect_text(str(msg.content))
                # 如果百度审核已给出明确结论，直接返回结果
                if risk != RiskLevel.Pass:
                    return CensorResult(msg, risk, reasons or set(), extra) if extra else CensorResult(msg, risk, reasons or set())
            
            # 使用主审核器检查
            risk, reasons = await self._text_censor.detect_text(str(msg.content))
            # 过滤空的原因集合
            return CensorResult(msg, risk, reasons or set(), extra) if extra else CensorResult(msg, risk, reasons or set())
        except Exception as e:
            logger.error(f"处理文本审核任务时发生错误: {e!s}")
            return CensorResult(msg, RiskLevel.Review, {f"{e!s}"})

    async def submit_text_with_baidu(
        self,
        content: str,
        source: str,
        extra: dict[str, Any] | None = None,
    ) -> CensorResult:
        """
        使用百度内容安全API提交文本审核任务

        参数:
            content: 待审核的文本内容
            source: 文本来源
            extra: 可选的额外信息字典

        返回:
            CensorResult: 审核结果对象
        """
        if not self._baidu_censor:
            raise RuntimeError("百度内容安全审核器未成功初始化，请检查配置")

        msg = Message(content, source)
        try:
            risk, reasons = await self._baidu_censor.detect_text(str(msg.content))
            return CensorResult(msg, risk, reasons or set(), extra) if extra else CensorResult(msg, risk, reasons or set())
        except Exception as e:
            logger.error(f"使用百度API处理文本审核任务时发生错误: {e!s}")
            return CensorResult(msg, RiskLevel.Review, {f"{e!s}"})

    async def submit_image(
        self,
        content: str,
        source: str,
    ) -> CensorResult:
        """
        提交图片审核任务

        参数:
            content: 待审核的图片内容（通常是URL或路径）
            source: 图片来源

        返回:
            CensorResult: 审核结果对象
        """
        if not self._image_censor:
            raise RuntimeError("图片审核未启用或未成功初始化，请检查配置")

        if "multimedia.nt.qq.com.cn" in content:
            content = content.replace("https://", "http://")

        msg = Message(content, source)

        img_b64_a = None
        img_b64_b = None
        if content.startswith("http"):
            try:
                async def down_img(url: str) -> bytes:
                    proxy = os.getenv("HTTP_PROXY") or os.getenv("HTTPS_PROXY")
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, proxy=proxy) as resp:
                            return await resp.read()

                image_data = await down_img(content)
                img_b64 = base64.b64encode(image_data).decode("utf-8")

                if fmt := get_image_format(img_b64):
                    img_b64_a = f"data:image/{fmt};base64,{img_b64}"
                    msg.content = img_b64_a
                img_b64_b = f"base64://{img_b64}"
            except Exception as e:
                logger.error(f"下载图片时发生错误: {e!s}")

        try:
            # 优先使用百度审核（如果配置）
            if self._baidu_censor:
                risk, reasons = await self._baidu_censor.detect_image(content)
                # 如果百度审核已给出明确结论，直接返回结果
                if risk != RiskLevel.Pass:
                    return CensorResult(msg, risk, reasons or set())

            # 使用主审核器检查
            risk, reasons = await self._image_censor.detect_image(content)
            # 过滤空的原因集合
            return CensorResult(msg, risk, reasons or set())
        except Exception as e:
            logger.error(f"初次处理图片审核任务时发生错误: {e!s}")

            # 如果首次失败且有备用格式，尝试使用备用格式
            if img_b64_b:
                try:
                    risk, reasons = await self._image_censor.detect_image(img_b64_b)
                    # 过滤空的原因集合
                    return CensorResult(msg, risk, reasons or set())
                except Exception as e2:
                    logger.error(f"再次处理图片审核任务时发生错误: {e2!s}")
                    return CensorResult(msg, RiskLevel.Review, {f"{e2!s}"})
            return CensorResult(msg, RiskLevel.Review, {f"{e!s}"})

    async def submit_image_with_baidu(
        self,
        content: str,
        source: str,
    ) -> CensorResult:
        """
        使用百度内容安全API提交图片审核任务

        参数:
            content: 待审核的图片内容（通常是URL或路径）
            source: 图片来源

        返回:
            CensorResult: 审核结果对象
        """
        if not self._baidu_censor:
            raise RuntimeError("百度内容安全审核器未成功初始化，请检查配置")

        msg = Message(content, source)
        try:
            risk, reasons = await self._baidu_censor.detect_image(content)
            return CensorResult(msg, risk, reasons or set())
        except Exception as e:
            logger.error(f"使用百度API处理图片审核任务时发生错误: {e!s}")
            return CensorResult(msg, RiskLevel.Review, {f"{e!s}"})

    async def submit_userid(
        self,
        userid: str,
        source: str,
    ) -> CensorResult:
        """
        提交用户ID识别任务

        参数:
            userid: 待识别的用户ID
            source: 用户ID来源

        返回:
            CensorResult: 识别结果对象
        """
        msg = Message(userid, source)
        try:
            # 调用用户ID审核器检测
            risk, reasons = await self._userid_censor.detect_text(str(msg.content))
            return CensorResult(
                msg, risk, {f"黑名单用户{str(reasons)[1:-1]}"} if reasons else set()
            )
        except Exception as e:
            logger.error(f"处理用户ID识别任务时发生错误: {e!s}")
            return CensorResult(msg, RiskLevel.Review, {f"{e!s}"})

    async def close(self) -> None:
        """清理资源

        关闭所有审核器的连接，释放资源
        """
        try:
            if self._text_censor:
                await self._text_censor.close()
            if self._image_censor and self._image_censor is not self._text_censor:
                await self._image_censor.close()
            if self._userid_censor:
                await self._userid_censor.close()
            if self._baidu_censor:
                await self._baidu_censor.close()
        except Exception as e:
            logger.error(f"关闭时出错: {e!s}")
