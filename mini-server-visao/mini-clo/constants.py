"""
mini-КЛО constants — ported from main КЛО scoring_engine.py.

Lang/country hard-kill map. See LANG_HARDKILL_MAP + LANG_HARDKILL_ENGLISH_COUNTRIES.
"""
from typing import Optional


# English default lang on many Android OEMs — wide whitelist to not FP legit
# users. Expanded 2026-06-23 for EU/LATAM/Africa.
LANG_HARDKILL_ENGLISH_COUNTRIES = {
    "US", "GB", "AU", "CA", "NZ", "IE",
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IS", "IT", "LV", "LT", "LU", "MT", "NL", "NO", "PL", "PT", "RO",
    "SK", "SI", "ES", "SE", "CH", "LI",
    "MQ", "GP", "GF", "RE", "YT", "PF", "NC", "BL", "MF", "PM", "WF",
    "NG", "GH", "KE", "UG", "ZA", "ZM", "BW", "TZ", "ZW", "MW",
    "SL", "LR", "GM", "ET", "RW", "NA", "CI", "SN",
    "PH", "IN", "PK", "BD", "SG", "MY", "HK", "ID", "VN", "TH",
    "JM", "TT", "BS", "BR", "AR", "MX", "CL", "PE", "CO", "VE", "EC", "UY",
    "PY", "BO", "GT", "HN", "SV", "NI", "CR", "PA", "DO", "CU", "PR",
    "TR", "RU", "UA", "BY", "MD", "AM", "AZ", "GE", "KZ", "UZ", "KG", "TJ",
    "IL", "AE", "SA", "EG", "MA", "DZ", "TN",
}

LANG_HARDKILL_MAP = {
    "ru": {"RU", "BY", "KZ", "KG", "UA", "UZ", "TJ", "MD", "AM", "AZ", "GE"},
    "tr": {"TR", "CY", "AZ"},
    "uk": {"UA"},
    "kk": {"KZ"},
    "uz": {"UZ"},
    "az": {"AZ"},
    "de": {"DE", "AT", "CH", "LI", "LU"},
    "fr": {"FR", "BE", "CH", "CA", "LU", "MC", "MQ", "GP", "RE", "GF",
           "CI", "SN", "ML", "CM", "CG", "CD", "MG", "HT", "TN", "DZ", "MA",
           "BF", "BJ", "TG", "NE", "GA", "GN", "MR"},
    "es": {"ES", "MX", "AR", "CO", "CL", "PE", "VE", "EC", "UY", "PY",
           "BO", "GT", "HN", "SV", "NI", "CR", "PA", "DO", "CU", "PR"},
    "pt": {"BR", "PT", "AO", "MZ", "CV", "GW", "ST", "TL"},
    "it": {"IT", "CH", "VA", "SM", "MT"},
    "pl": {"PL"},
    "nl": {"NL", "BE", "SR"},
    "sv": {"SE", "FI"},
    "no": {"NO"},
    "fi": {"FI"},
    "da": {"DK"},
    "is": {"IS"},
    "cs": {"CZ"},
    "sk": {"SK"},
    "hu": {"HU"},
    "ro": {"RO", "MD"},
    "bg": {"BG"},
    "hr": {"HR"},
    "sl": {"SI"},
    "sr": {"RS"},
    "el": {"GR", "CY"},
    "lt": {"LT"},
    "lv": {"LV"},
    "et": {"EE"},
    "sq": {"AL", "XK"},
    "mk": {"MK"},
    "bs": {"BA"},
    "ka": {"GE"},
    "hy": {"AM"},
    "ar": {"SA", "AE", "EG", "IQ", "JO", "KW", "QA", "BH", "OM", "LB",
           "SY", "YE", "LY", "TN", "DZ", "MA", "SD", "MR"},
    "he": {"IL"},
    "fa": {"IR", "AF", "TJ"},
    "ur": {"PK", "IN"},
    "hi": {"IN"},
    "vi": {"VN"},
    "th": {"TH"},
    "id": {"ID"},
    "ms": {"MY", "SG", "BN", "ID"},
    "ja": {"JP"},
    "ko": {"KR"},
    "zh": {"CN", "TW", "HK", "SG", "MO"},
}


def check_lang_country_mismatch(accept_language: str, country: str) -> Optional[str]:
    """Returns None if OK, else reason string. Ported from main КЛО."""
    if not accept_language or not country:
        return None
    country_upper = country.upper()
    lang_codes = []
    for part in accept_language.split(","):
        primary = part.strip().split(";")[0]
        code = primary.split("-")[0].lower().strip()
        if code and len(code) == 2 and code not in lang_codes:
            lang_codes.append(code)
    if not lang_codes:
        return None
    any_recognized = False
    failed_langs = []
    for code in lang_codes:
        expected = (LANG_HARDKILL_ENGLISH_COUNTRIES if code == "en"
                    else LANG_HARDKILL_MAP.get(code, set()))
        if not expected:
            continue
        any_recognized = True
        if country_upper in expected:
            return None
        failed_langs.append(code)
    if not any_recognized:
        return None
    return f"langs {failed_langs} do not match country '{country_upper}'"
