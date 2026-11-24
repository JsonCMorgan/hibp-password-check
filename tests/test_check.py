from hibp_password_check.check import lookup_pwned_count, sha1_password


def test_sha1_format():
    assert sha1_password("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_lookup_mock():
    suffix = sha1_password("password")[5:]

    def fake(_prefix: str) -> str:
        return f"{suffix}:3730471\nOTHER000:1"

    r = lookup_pwned_count("password", fetch=fake)
    assert r["pwned"]
    assert r["count"] == 3730471


def test_lookup_clean_mock():
    def fake(_prefix: str) -> str:
        return "ZZZZZZ:1"

    r = lookup_pwned_count("not-in-list-xyz", fetch=fake)
    assert not r["pwned"]
    assert r["count"] == 0