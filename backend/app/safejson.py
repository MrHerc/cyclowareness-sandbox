"""Values JSON can carry, and the ones it cannot.

`json.loads` accepts `NaN`, `Infinity` and `-Infinity` — they are what
`json.dumps` emits by default, so any caller using a stock library can send
them. Starlette hard-codes `allow_nan=False` on the way out. So a non-finite
float is easy to get IN and impossible to get back OUT: it is accepted, stored,
and then every response that includes it is a **500 in text/plain**, which is
the one error shape no client of this API handles.

Measured: a dynamic report whose `facts` carried one `NaN` was accepted with a
200, and afterwards `export.json` and `export.signed` returned 500 for that job
permanently — the signed evidence copy, unreachable, because of a number in a
free-form dict written by the detonation worker.

Very large integers are the same failure with a different shape: Python has no
integer ceiling, JSON does not either, and `float()` on one raises OverflowError
in whatever tries to do arithmetic with it later.
"""
from __future__ import annotations

import math
from typing import Any

#: Beyond this, `float(value)` raises rather than returning `inf`.
_FLOAT_MAX = 1.7976931348623157e308


def json_safe(value: Any) -> Any:
    """The same value, with anything JSON cannot round-trip rendered as text.

    Rendered, not dropped: an analyst reading a report should still see that the
    worker reported `inf` for something. Losing the observation to protect the
    serialiser would be trading one silent wrong answer for another.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, float) and not math.isfinite(value):
        return repr(value)
    if isinstance(value, int) and abs(value) > _FLOAT_MAX:
        return str(value)
    # A NUL INSIDE A JSON COLUMN POISONS EVERY QUERY OVER THE TABLE.
    #
    # `db_text` strips NULs on the way into TEXT columns because psycopg refuses
    # them outright. The JSON columns take a different route: PostgreSQL stores
    # a NUL inside a `json` value happily, and then EVERY `::jsonb` cast over
    # `sandbox_jobs` fails -- "unsupported Unicode escape sequence" -- because
    # `jsonb` has no representation for it. One sample-controlled byte, in a
    # filename or a YARA rule name or a signal detail, and the whole table stops
    # answering the queries the API, the retention sweep and this audit run.
    #
    # Replaced with the escaped text rather than dropped, for the same reason
    # `inf` is rendered rather than discarded: the observation that the sample
    # contained a NUL is itself worth keeping.
    if isinstance(value, str):
        return value.replace("\x00", "\\u0000") if "\x00" in value else value
    if isinstance(value, dict):
        return {
            (k.replace("\x00", "\\u0000") if isinstance(k, str) else k): json_safe(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    return value
