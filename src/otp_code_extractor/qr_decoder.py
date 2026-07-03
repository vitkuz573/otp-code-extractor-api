"""QR decoder wrapper around qreader + opencv-python-headless.

The decoder is **lazy** — the underlying ``QReader`` instance is only built on
first use, which keeps test setup fast and avoids downloading the model when
the feature is not exercised (e.g. when only ``from-secret`` is called).
"""

from __future__ import annotations

import threading
from typing import Any

from .exceptions import QrDecodeError, QrDisabledError
from .logging_config import get_logger

logger = get_logger(__name__)


_MIME_TO_FLAG = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/bmp": ".bmp",
    "image/webp": ".webp",
    "image/tiff": ".tif",
}


class QrDecoder:
    """Thread-safe lazy loader for a ``qreader.QReader`` instance."""

    def __init__(self, model_id: str = "detector_v1") -> None:
        self._model_id = model_id
        self._lock = threading.Lock()
        self._reader: Any | None = None

    def _ensure_reader(self) -> Any:
        if self._reader is not None:
            return self._reader
        with self._lock:
            if self._reader is not None:
                return self._reader
            try:
                from qreader import QReader  # type: ignore[import-untyped]
            except ImportError as exc:  # pragma: no cover - guarded by requirements
                raise QrDisabledError(
                    "qreader is not installed; enable requirements or set "
                    "OTP_EXTRACTOR_QR_DECODER_ENABLED=false"
                ) from exc
            logger.info("loading_qreader", model=self._model_id)
            self._reader = QReader()
            return self._reader

    def decode(self, image_bytes: bytes, mime_type: str | None = None) -> list[str]:
        """Decode all QR-like payloads in ``image_bytes``.

        Returns an empty list when nothing is detected. Raises ``QrDecodeError``
        when the image cannot be read at all.
        """
        if not image_bytes:
            raise QrDecodeError("Empty image payload")
        try:
            import cv2  # type: ignore[import-untyped]
            import numpy as np  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover
            raise QrDisabledError(f"opencv-python is required for QR decoding: {exc}") from exc

        arr = np.frombuffer(image_bytes, dtype=np.uint8)
        if mime_type and mime_type.lower() in _MIME_TO_FLAG:
            img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        else:
            img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            raise QrDecodeError("Could not decode the supplied image")

        reader = self._ensure_reader()
        try:
            results = reader.detect_and_decode(image=img)
        except Exception as exc:  # noqa: BLE001
            raise QrDecodeError(f"QR decoder failed: {exc}") from exc

        if not results:
            return []
        return [r for r in results if r]


# ---------------------------------------------------------------------------
# Module-level singleton + convenience helpers
# ---------------------------------------------------------------------------


_decoder: QrDecoder | None = None
_decoder_lock = threading.Lock()


def get_decoder() -> QrDecoder:
    """Return the shared ``QrDecoder`` instance."""
    global _decoder
    if _decoder is not None:
        return _decoder
    with _decoder_lock:
        if _decoder is None:
            _decoder = QrDecoder()
        return _decoder


def reset_decoder_for_tests() -> None:
    """Discard the cached decoder instance."""
    global _decoder
    with _decoder_lock:
        _decoder = None


def decode_qr_image_bytes(
    image_bytes: bytes, *, mime_type: str | None = None
) -> list[str]:
    """Decode QR codes from raw image bytes."""
    return get_decoder().decode(image_bytes, mime_type=mime_type)


def decode_qr_image_b64(b64_payload: str, *, mime_type: str | None = None) -> list[str]:
    """Decode QR codes from a base64-encoded image payload."""
    import base64
    import binascii

    try:
        image_bytes = base64.b64decode(b64_payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise QrDecodeError(f"Invalid base64 payload: {exc}") from exc
    return decode_qr_image_bytes(image_bytes, mime_type=mime_type)
