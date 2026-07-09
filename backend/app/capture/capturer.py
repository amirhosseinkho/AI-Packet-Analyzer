from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from typing import Optional

from app.capture.filters import CaptureFilter
from app.capture.parser import ParsedPacket, parse_scapy_packet
from app.config import get_settings
from app.logger import get_logger

log = get_logger(__name__)
settings = get_settings()


class PacketCapturer:
    """Asynchronous wrapper around Scapy's live capture.

    Packets are yielded through an asyncio.Queue so that the FastAPI event
    loop is never blocked by the libpcap I/O thread.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        capture_filter: Optional[CaptureFilter] = None,
        batch_size: int = 100,
    ) -> None:
        self.interface = interface or settings.capture_interface
        self.filter = capture_filter or CaptureFilter.default()
        self.batch_size = batch_size
        self._queue: asyncio.Queue[Optional[ParsedPacket]] = asyncio.Queue(maxsize=10_000)
        self._running = False
        self._capture_task: Optional[asyncio.Task[None]] = None
        self._last_packet_time: Optional[float] = None
        self._total_captured = 0
        self._total_dropped = 0

    # ── Public API ────────────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        loop = asyncio.get_running_loop()
        self._capture_task = loop.create_task(self._run_capture(loop))
        log.info("Packet capture started", interface=self.interface, filter=self.filter.to_bpf())

    async def stop(self) -> None:
        self._running = False
        if self._capture_task:
            self._capture_task.cancel()
            try:
                await self._capture_task
            except asyncio.CancelledError:
                pass
        await self._queue.put(None)  # sentinel
        log.info("Packet capture stopped", total=self._total_captured, dropped=self._total_dropped)

    async def packets(self) -> AsyncGenerator[ParsedPacket, None]:
        while True:
            pkt = await self._queue.get()
            if pkt is None:
                break
            yield pkt

    @property
    def stats(self) -> dict[str, int]:
        return {
            "total_captured": self._total_captured,
            "total_dropped": self._total_dropped,
            "queue_size": self._queue.qsize(),
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _run_capture(self, loop: asyncio.AbstractEventLoop) -> None:
        try:
            await loop.run_in_executor(None, self._blocking_capture, loop)
        except Exception as exc:
            log.error("Capture thread crashed", error=str(exc))
            self._running = False

    def _blocking_capture(self, loop: asyncio.AbstractEventLoop) -> None:
        try:
            from scapy.sendrecv import AsyncSniffer
        except ImportError as exc:
            log.error("Scapy not installed", error=str(exc))
            return

        bpf = self.filter.to_bpf()

        def _callback(raw_pkt: object) -> None:
            if not self._running:
                return

            now = datetime.now(tz=timezone.utc).timestamp()
            iat = now - self._last_packet_time if self._last_packet_time else None
            self._last_packet_time = now

            parsed = parse_scapy_packet(raw_pkt)
            if parsed is None:
                return

            parsed.inter_arrival_time = iat
            self._total_captured += 1

            try:
                loop.call_soon_threadsafe(self._queue.put_nowait, parsed)
            except asyncio.QueueFull:
                self._total_dropped += 1
                log.warning("Capture queue full, dropping packet")

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter=bpf or None,
            prn=_callback,
            store=False,
        )
        sniffer.start()
        # Block this executor thread until stop() sets _running = False
        import time

        while self._running:
            time.sleep(0.1)
        sniffer.stop()


# ── Singleton ─────────────────────────────────────────────────────────────────
_capturer: Optional[PacketCapturer] = None


def get_capturer() -> PacketCapturer:
    global _capturer
    if _capturer is None:
        _capturer = PacketCapturer()
    return _capturer
