"""QR decoder wrapper.

Primary decoder: ``cv2.QRCodeDetector`` (and its multi variant) — pure
opencv, no system libs required. Works on every platform OpenCV runs on.

Optional fallback: ``qreader`` (a YOLO-based detector) is loaded lazily only
if cv2 fails to detect anything. This keeps the default code path portable
while still benefiting from qreader's stronger model when the input is
blurry, rotated, or otherwise degraded.
"""

from __future__ import annotations

import base64
import binascii
import threading
from typing import Any

from .exceptions import QrDecodeError, QrDisabledError
from .logging_config import get_logger

logger = get_logger(__name__)


class QrDecoder:
    """Thread-safe QR decoder backed by opencv (and optionally qreader)."""

    def __init__(self, model_id: str = "detector_v1") -> None:
        self._model_id = model_id
        self._lock = threading.Lock()
        self._qreader: Any | None = None
        self._qreader_attempted = False

    def _ensure_qreader(self) -> Any:
        """Load the qreader model on demand; return None on failure."""
        if self._qreader is not None:
            return self._qreader
        if self._qreader_attempted:
            return None
        with self._lock:
            if self._qreader_attempted:
                return self._qreader
            try:
                from qreader import QReader  # type: ignore[import-untyped]
            except Exception as exc:  # noqa: BLE001
                logger.debug("qreader_unavailable", extra={"err": str(exc)})
                self._qreader_attempted = True
                return None
            try:
                self._qreader = QReader()
            except Exception as exc:  # noqa: BLE001
                logger.debug("qreader_load_failed", extra={"err": str(exc)})
                self._qreader = None
            self._qreader_attempted = True
            return self._qreader

    def decode(self, image_bytes: bytes, mime_type: str | None = None) -> list[str]:
        """Decode all QR-like payloads in ``image_bytes``.

        Returns an empty list when nothing is detected. Raises ``QrDecodeError``
        when the image cannot be read at all.
        """
        if not image_bytes:
            raise QrDecodeError("Empty image payload")

        img = self._decode_image(image_bytes, mime_type)
        if img is None:
            raise QrDecodeError("Could not decode the supplied image")

        results = self._decode_with_opencv(img)
        if results:
            return results

        reader = self._ensure_qreader()
        if reader is None:
            return []
        try:
            qreader_results = reader.detect_and_decode(image=img)
        except Exception as exc:  # noqa: BLE001
            logger.debug("qreader_decode_failed", extra={"err": str(exc)})
            return []
        return [r for r in (qreader_results or []) if r]

    @staticmethod
    def _decode_image(image_bytes: bytes, mime_type: str | None) -> Any | None:
        try:
            import cv2  # type: ignore[import-untyped]
            import numpy as np  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover
            raise QrDisabledError(f"opencv-python is required for QR decoding: {exc}") from exc

        arr = np.frombuffer(image_bytes, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        return img

    @staticmethod
    def _decode_with_opencv(img: Any) -> list[str]:
        try:
            import cv2  # type: ignore[import-untyped]
        except ImportError:  # pragma: no cover
            return []
        results: list[str] = []
        try:
            multi = cv2.QRCodeDetectorAruco() if hasattr(cv2, "QRCodeDetectorAruco") else None
            detector = multi if multi is not None else cv2.QRCodeDetector()
        except Exception:  # noqa: BLE001
            detector = cv2.QRCodeDetector()

        if hasattr(detector, "detectAndDecodeMulti"):
            try:
                ok, decoded_info, _points = detector.detectAndDecodeMulti(img)
            except Exception:  # noqa: BLE001
                ok, decoded_info = False, []
            if ok and decoded_info:
                results.extend(d for d in decoded_info if d)

        if not results:
            try:
                data, _vertices, _straight = detector.detectAndDecode(img)
            except Exception:  # noqa: BLE001
                data = ""
            if data:
                results.append(data)
        return results


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


def decode_qr_image_bytes(image_bytes: bytes, *, mime_type: str | None = None) -> list[str]:
    """Decode QR codes from raw image bytes."""
    return get_decoder().decode(image_bytes, mime_type=mime_type)


def decode_qr_image_b64(b64_payload: str, *, mime_type: str | None = None) -> list[str]:
    """Decode QR codes from a base64-encoded image payload."""
    try:
        image_bytes = base64.b64decode(b64_payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise QrDecodeError(f"Invalid base64 payload: {exc}") from exc
    return decode_qr_image_bytes(image_bytes, mime_type=mime_type)
