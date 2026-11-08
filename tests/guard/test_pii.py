import pytest

from app.agents.guard.pii.detectors import PIIDetector, luhn_valid, verhoeff_check_digit, verhoeff_valid
from app.agents.guard.pii.vault import FieldPolicy, PIIVault, apply_policies, storage_value

DET = PIIDetector()


def types(text):
    return [(s.entity_type, s.text) for s in DET.detect(text)]


def make_aadhaar(prefix="23412341234"):
    return prefix + verhoeff_check_digit(prefix)


def test_verhoeff():
    a = make_aadhaar()
    assert verhoeff_valid(a)
    bad = a[:-1] + str((int(a[-1]) + 1) % 10)
    assert not verhoeff_valid(bad)


def test_aadhaar_requires_checksum():
    a = make_aadhaar("49981234567")
    assert ("AADHAAR", f"{a[:4]} {a[4:8]} {a[8:]}") in types(f"my aadhaar is {a[:4]} {a[4:8]} {a[8:]}")
    bad = a[:-1] + str((int(a[-1]) + 1) % 10)
    assert not any(t == "AADHAAR" for t, _ in types(f"order {bad}"))


def test_pan():
    assert ("PAN", "ABCPE1234F") in types("PAN: ABCPE1234F")
    assert ("PAN", "abcpe1234f") in types("pan abcpe1234f")


def test_upi_not_mislabelled_as_email():
    t = types("pay me at rabin@okhdfcbank or 9876543210@ybl, email rabin@gmail.com")
    assert ("UPI_ID", "rabin@okhdfcbank") in t
    assert ("UPI_ID", "9876543210@ybl") in t
    assert ("EMAIL", "rabin@gmail.com") in t
    assert ("EMAIL", "rabin@okhdfcbank") not in t


@pytest.mark.parametrize("card", ["4111 1111 1111 1111", "5500-0000-0000-0004", "378282246310005"])
def test_card_luhn(card):
    assert ("CREDIT_CARD", card) in types(f"card {card}")


def test_card_rejects_bad_luhn():
    assert not luhn_valid("4111111111111112")
    assert not any(t == "CREDIT_CARD" for t, _ in types("ref 4111 1111 1111 1112"))


def test_ifsc_vehicle_passport():
    assert ("IFSC", "HDFC0001234") in types("IFSC HDFC0001234")
    assert ("VEHICLE_NUMBER", "KA 01 AB 1234") in types("car KA 01 AB 1234 parked outside")
    assert ("VEHICLE_NUMBER", "22 BH 1234 AA") in types("bike 22 BH 1234 AA")
    assert ("PASSPORT", "J8369854") in types("passport number J8369854")
    assert not any(t == "PASSPORT" for t, _ in types("order J8369854 status"))  # needs context


@pytest.mark.parametrize("text,phone", [
    ("call 9876543210", "9876543210"),
    ("call +91 98765 43210", "+91 98765 43210"),
    ("whatsapp 98765-43210", "98765-43210"),
])
def test_phone(text, phone):
    assert ("PHONE", phone) in types(text)


@pytest.mark.parametrize("text", [
    "budget is ₹250000 for the renovation",
    "budget ₹ 250000",
    "costs Rs.250000",
    "order 560034 hasn't arrived",
    "order id: 560034",
    "invoice #560034",
    "paid 250000 rupees",
])
def test_pin_code_false_positives(text):
    assert not any(t == "PIN_CODE" for t, _ in types(text))


@pytest.mark.parametrize("text", [
    "pincode 560034", "deliver to 560034", "Indiranagar, Bangalore 560038", "PIN: 700001",
])
def test_pin_code_true_positives(text):
    assert any(t in ("PIN_CODE", "ADDRESS") for t, _ in types(text))


def test_address_and_name_heuristics():
    t = dict(types("My name is Priya Sharma. Flat 302, Prestige Towers, 5th Cross, Indiranagar, Bangalore 560038."))
    assert t["PERSON"] == "Priya Sharma"
    assert t["ADDRESS"].startswith("Flat 302") and t["ADDRESS"].endswith("560038")


def test_address_ignores_prices():
    t = dict(types("budget ₹2500, flat 302 Prestige Towers"))
    assert t["ADDRESS"].lower().startswith("flat 302")


def test_name_stopwords():
    assert types("I am Looking for a maid") == []


def test_reversible_masking_roundtrip():
    text = "call 9876543210 or 9876543210, mail a@b.com"
    v = PIIVault()
    r = apply_policies(text, DET.detect(text), {}, v)
    assert r.masked_text == "call <PHONE_1> or <PHONE_1>, mail <EMAIL_1>"
    assert v.unmask(r.masked_text) == text
    assert v.unmask_obj({"to": "<PHONE_1>", "cc": ["< EMAIL_1 >"]}) == {"to": "9876543210", "cc": ["a@b.com"]}
    assert "9876543210" not in r.log_text and "[PHONE]" in r.log_text


def test_policies_drop_allow_mask():
    a = make_aadhaar()
    text = f"aadhaar {a}, pincode 560034, phone 9876543210"
    v = PIIVault()
    pols = {"AADHAAR": FieldPolicy(llm="drop"), "PIN_CODE": FieldPolicy(llm="allow")}
    r = apply_policies(text, DET.detect(text), pols, v)
    assert "[AADHAAR_REMOVED]" in r.masked_text and a not in r.masked_text
    assert "560034" in r.masked_text
    assert "<PHONE_1>" in r.masked_text
    assert v.resolve("<AADHAAR_1>") is None  # dropped values are not recoverable
    assert "560034" not in r.log_text  # logs redact even "allow" fields


def test_storage_policies():
    span = DET.detect("call 9876543210")[0]
    key = b"k"
    assert storage_value(span, FieldPolicy(store="none"), key) is None
    h = storage_value(span, FieldPolicy(store="hash"), key)
    assert len(h) == 64 and "9876" not in h

    class ReverseEncryptor:  # stands in for KMS
        def encrypt(self, data: bytes) -> bytes:
            return data[::-1]

        def decrypt(self, data: bytes) -> bytes:
            return data[::-1]

    enc = ReverseEncryptor()
    ct = storage_value(span, FieldPolicy(store="encrypt"), key, enc)
    assert enc.decrypt(ct.encode()).decode() == "9876543210"
    with pytest.raises(RuntimeError):
        storage_value(span, FieldPolicy(store="encrypt"), key, None)
