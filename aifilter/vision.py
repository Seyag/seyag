"""AI image review with the open-source NudeNet detector (runs locally)."""

import io

import numpy as np

EXPLICIT = {
    "FEMALE_GENITALIA_EXPOSED", "MALE_GENITALIA_EXPOSED", "FEMALE_BREAST_EXPOSED",
    "BUTTOCKS_EXPOSED", "ANUS_EXPOSED",
}
MODEST_EXTRA = {
    "BELLY_EXPOSED", "ARMPITS_EXPOSED", "BUTTOCKS_COVERED", "FEMALE_BREAST_COVERED",
    "FEMALE_GENITALIA_COVERED", "MALE_BREAST_EXPOSED",
}


def blocked_labels(level: str, block_female_faces: bool) -> set[str]:
    labels = set(EXPLICIT)
    if level == "modest":
        labels |= MODEST_EXTRA
    if block_female_faces:
        labels.add("FACE_FEMALE")
    return labels


def decode(data: bytes):
    """Compatibility helper: first sampled frame, resized before inference."""
    return next(decode_frames(data))


def decode_frames(data: bytes):
    """Sample first/middle/last animation frames (at most 3).

    Pillow composites GIF/WebP/APNG frames when seeking. Never upscale and never
    change global truncated-image settings: malformed data must raise.
    """
    from PIL import Image
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(io.BytesIO(data)) as img:
            count = getattr(img, "n_frames", 1)
            start = 1 if img.info.get("default_image", False) and count > 1 else 0
            for index in sorted({start, start + (count - 1 - start) // 2, count - 1}):
                img.seek(index)
                frame = img.copy()
                frame.thumbnail((640, 640))
                rgb = np.asarray(frame.convert("RGB"))
                yield rgb[:, :, ::-1].copy()


class Reviewer:
    def __init__(self, level="modest", min_score=0.45, block_female_faces=False):
        from nudenet import NudeDetector

        self._detector = NudeDetector()
        self.min_score = min_score
        self.labels = blocked_labels(level, block_female_faces)

    def review(self, data: bytes) -> tuple[bool, list[str]]:
        """Return (bad, matched labels). Undecodable data raises ValueError."""
        try:
            frames = list(decode_frames(data))
        except Exception as e:  # noqa: BLE001 - any decoder failure means "not readable"
            raise ValueError(f"undecodable image: {e}") from e
        hits = [
            f"{d['class']}:{d['score']:.2f}"
            for mat in frames for d in self._detector.detect(mat)
            if d["class"] in self.labels and d["score"] >= self.min_score
        ]
        return bool(hits), hits
