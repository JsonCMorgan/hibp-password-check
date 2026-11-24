# HIBP Password Check

[![CI](https://github.com/JsonCMorgan/hibp-password-check/actions/workflows/ci.yml/badge.svg)](https://github.com/JsonCMorgan/hibp-password-check/actions/workflows/ci.yml)

## For mentors (30 seconds)

**What it is:** Check whether a password shows up in [Have I Been Pwned](https://haveibeenpwned.com/) **Pwned Passwords** using **k-anonymity**: only the first 5 characters of the SHA-1 hash are sent to the API.

**Why it exists:** Privacy-aware credential hygiene story for interviews. Not integrated into Boundry MSSP.

```powershell
pip install -e ".[dev]"
pytest -q
python -m hibp_password_check
```

For automation (avoid argv history): `$env:HIBP_CHECK_PASSWORD='...'; python -m hibp_password_check`

## License

MIT