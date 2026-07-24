"""The analysis engine.

Everything under this package speaks one vocabulary (``contracts.py``) and
obeys one rule: **a sample is never executed here.** Static parsers and YARA
run in-process; anything that would run the sample (the native engine, an
attached open-source sandbox) happens off-host through the ``native.py`` seam
and is merged back as ordinary Signals.
"""
