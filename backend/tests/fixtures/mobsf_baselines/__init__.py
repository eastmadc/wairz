"""MobSF manifest baseline fixtures for APK security scan comparison.

Each JSON fixture file contains the normalized MobSF baseline findings for a
well-known test APK.  The baselines document what MobSF reports for each APK's
manifest so that Wairz's own manifest scanner can be validated against a known
reference.

Fixture files:
  - diva_baseline.json         — DIVA (Damn Insecure and Vulnerable App)
  - insecurebankv2_baseline.json — InsecureBankv2
  - ovaa_baseline.json         — OVAA (Oversecured Vulnerable Android App)

Use ``extract_mobsf_baselines.py`` to regenerate these fixtures by running
Wairz's manifest scanner against mock APK objects and comparing against the
known MobSF expected findings.
"""
