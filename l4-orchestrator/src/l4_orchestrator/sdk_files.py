"""Connect completed producer files to Store, separately from native Tool errors."""
import base64

from agents import ToolOutputImage, ToolOutputText

from .json_values import dumps


class FileConnections:
    def __init__(self, *, producers=(), close_callbacks=(), screenshots=None):
        self.producers = tuple(producers)
        self.close_callbacks = tuple(close_callbacks)
        self.screenshots = screenshots

    async def register_completed(self, store):
        for producer in self.producers:
            for completed in producer.completed_files():
                await store.register_file(completed)

    async def close(self, store):
        # NetworkCapture.close() already waits for its pending capture/file work.
        for close in self.close_callbacks:
            await close()
        await self.register_completed(store)

    async def tool_output(self, tool_name, reply):
        text = dumps(reply)
        if tool_name != "capture_screenshot" or reply["status"] != "success":
            return text
        image_url = await self.screenshot_url(reply["data"]["result"])
        return [ToolOutputText(text=text), ToolOutputImage(image_url=image_url, detail="auto")]

    async def screenshot_url(self, image):
        """Deliver the same saved PNG to a model, including the initial manager input."""
        if self.screenshots is None:
            raise ImageDeliveryError("A screenshot reader is required to deliver actual PNG pixels")
        try:
            png = await self.screenshots.load_png(image["artifact_ref"], image["sha256"])
        except (OSError, ValueError, KeyError) as exc:
            raise ImageDeliveryError(str(exc)) from exc
        return "data:image/png;base64," + base64.b64encode(png).decode("ascii")


class ImageDeliveryError(RuntimeError):
    pass
