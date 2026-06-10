from telethon import TelegramClient
from telethon.tl.types import Channel
from datetime import datetime
import json
import asyncio


class TelegramCollector:

    def __init__(self, config_file="telegram_config.json"):

        with open(config_file) as f:
            cfg = json.load(f)

        self.api_id = cfg["api_id"]
        self.api_hash = cfg["api_hash"]

        self.client = TelegramClient(
            "telegram_session",
            self.api_id,
            self.api_hash
        )

    async def _collect_messages(
        self,
        channels,
        limit=50
    ):

        results = []

        await self.client.start()

        for channel in channels:

            try:

                entity = await self.client.get_entity(channel)

                count = 0

                async for msg in self.client.iter_messages(
                    entity,
                    limit=limit
                ):

                    if not msg.text:
                        continue

                    results.append({
                        "source": "telegram",
                        "message_id": str(msg.id),
                        "channel": channel,
                        "text": msg.text,
                        "views": getattr(msg, "views", 0),
                        "timestamp": (
                            msg.date.isoformat()
                            if msg.date
                            else ""
                        ),
                        "url": (
                            f"https://t.me/{channel}/{msg.id}"
                        ),
                        "collected_at":
                            datetime.now().isoformat()
                    })

                    count += 1

                print(
                    f"[Telegram] {channel}: "
                    f"{count} messages"
                )

            except Exception as e:

                print(
                    f"[Telegram] {channel}: {e}"
                )

        return results

    def collect_channels(
        self,
        channels,
        limit=50
    ):

        with self.client:
            return self.client.loop.run_until_complete(
                self._collect_messages(
                    channels,
                    limit
                )
            )
