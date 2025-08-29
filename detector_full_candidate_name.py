
import csv
import json
import re
import sys

# Regex patterns
RE_10_DIGIT = re.compile(r'(?<!\d)(\d{10})(?!\d)')
RE_AADHAR = re.compile(r'(?<!\d)(\d{4}\s?\d{4}\s?\d{4})(?!\d)')
RE_PASSPORT = re.compile(r'\b([A-Z][0-9]{7})\b')
RE_UPI = re.compile(r'\b([A-Za-z0-9._-]{2,})@([A-Za-z]{2,})\b')
RE_EMAIL = re.compile(r'\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b')
RE_IPV4 = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')

KEYS_STANDALONE_NUMERIC_EXCLUDE = {
    "transaction_id", "order_id", "product_id", "booking_reference", "warehouse_code",
    "gst_number", "ticket_id"
}

KEYS_NAME = {"name", "Name"}
KEYS_FIRST = {"first_name"}
KEYS_LAST = {"last_name"}
KEYS_EMAIL = {"email", "username", "Email"}
KEYS_ADDRESS = {"address", "address_proof", "Address"}
KEYS_CITY = {"city", "region"}
KEYS_STATE = {"state", "state_code"}
KEYS_PIN = {"pin_code"}
KEYS_DEVICE = {"device_id", "app_version"}
KEYS_IP = {"ip_address", "last_login"}
KEYS_PHONE = {"phone", "contact", "Phone"}
KEYS_UPI = {"upi_id"}

# Masking helpers
def mask_phone(s):
    m = RE_10_DIGIT.search(s)
    if not m:
        return s
    num = m.group(1)
    masked = num[:2] + "XXXXXX" + num[-2:]
    return s.replace(num, masked)

def mask_aadhar(s):
    return RE_AADHAR.sub(lambda m: "XXXX XXXX XXXX", s)

def mask_passport(s):
    return RE_PASSPORT.sub(lambda m: m.group(1)[0] + m.group(1)[1] + "XXXXX" + m.group(1)[-1], s)

def mask_upi(s):
    return RE_UPI.sub(lambda m: m.group(1)[:2] + "XXX@" + m.group(2), s)

def mask_email(s):
    return RE_EMAIL.sub(lambda m: m.group(1)[:2] + "XXX@" + m.group(2), s)

def mask_name(value):
    if not isinstance(value, str):
        return value
    parts = [p for p in value.strip().split() if p]
    if len(parts) < 2:
        return value
    masked_parts = [p[0] + "X" * (len(p) - 1) if len(p) > 1 else p for p in parts]
    return " ".join(masked_parts)

def mask_address(_):
    return "[REDACTED_ADDRESS]"

def mask_ip(_):
    return "x.x.x.x"

def mask_device(_):
    return "DEV-REDACTED"

def mask_string_value(val, *, redact_phone=False, redact_aadhar=False, redact_passport=False, redact_upi=False, redact_email=False, redact_ip=False):
    s = val
    if not isinstance(s, str):
        return s
    if redact_aadhar:
        s = mask_aadhar(s)
    if redact_passport:
        s = mask_passport(s)
    if redact_upi:
        s = mask_upi(s)
    if redact_email:
        s = mask_email(s)
    if redact_ip:
        s = RE_IPV4.sub(lambda _: "x.x.x.x", s)
    if redact_phone:
        s = mask_phone(s)
    return s

# Detection helpers
def has_full_name(value, first, last):
    has_two_words = False
    if isinstance(value, str):
        has_two_words = len(value.strip().split()) >= 2
    both = bool(first) and bool(last)
    return has_two_words or both

def looks_like_address(record_dict):
    if any(k in record_dict for k in KEYS_ADDRESS):
        return True
    has_city = any(k in record_dict and str(record_dict[k]).strip() for k in KEYS_CITY)
    has_pin = any(k in record_dict and str(record_dict[k]).strip() for k in KEYS_PIN)
    return has_city and has_pin

def contains_email(record_dict):
    for k in KEYS_EMAIL:
        if k in record_dict and isinstance(record_dict[k], str) and RE_EMAIL.search(record_dict[k]):
            return True
    for v in record_dict.values():
        if isinstance(v, str) and RE_EMAIL.search(v):
            return True
    return False

def contains_device_or_ip(record_dict):
    dev = any(k in record_dict and str(record_dict[k]).strip() for k in KEYS_DEVICE)
    ip = any(k in record_dict and isinstance(record_dict[k], str) and RE_IPV4.search(record_dict[k]) for k in KEYS_IP)
    return dev or ip

def contains_standalone_phone(value, key=None):
    if key and key.lower() in KEYS_STANDALONE_NUMERIC_EXCLUDE:
        return False
    if not isinstance(value, str):
        value = str(value)
    return bool(RE_10_DIGIT.search(value))

def contains_aadhar(value):
    return isinstance(value, str) and bool(RE_AADHAR.search(value))

def contains_passport(value):
    return isinstance(value, str) and bool(RE_PASSPORT.search(value))

def contains_upi(value):
    return isinstance(value, str) and bool(RE_UPI.search(value))

# Record-level evaluation
def evaluate_record(record_dict):
    flags = {
        "standalone_phone": False,
        "standalone_aadhar": False,
        "standalone_passport": False,
        "standalone_upi": False,
        "has_full_name": False,
        "has_email": False,
        "has_address": False,
        "has_device_or_ip": False
    }

    keys_with_pii = set()
    name_value = record_dict.get("Name") or record_dict.get("name")
    first_value = record_dict.get("first_name")
    last_value = record_dict.get("last_name")

    for k, v in list(record_dict.items()):
        if v is None:
            continue
        if contains_standalone_phone(v, key=k):
            flags["standalone_phone"] = True
            keys_with_pii.add(k)
        if contains_aadhar(v):
            flags["standalone_aadhar"] = True
            keys_with_pii.add(k)
        if contains_passport(v):
            flags["standalone_passport"] = True
            keys_with_pii.add(k)
        if contains_upi(v):
            flags["standalone_upi"] = True
            keys_with_pii.add(k)

    if has_full_name(name_value, first_value, last_value):
        flags["has_full_name"] = True
    if contains_email(record_dict):
        flags["has_email"] = True
    if looks_like_address(record_dict):
        flags["has_address"] = True
    if contains_device_or_ip(record_dict):
        flags["has_device_or_ip"] = True

    combo_count = 0
    core = 0
    if flags["has_full_name"]:
        core += 1
    if flags["has_email"]:
        core += 1
    if flags["has_address"]:
        core += 1
    combo_count = core
    if flags["has_device_or_ip"] and core >= 1:
        combo_count += 1

    standalone = flags["standalone_phone"] or flags["standalone_aadhar"] or flags["standalone_passport"] or flags["standalone_upi"]
    is_pii = standalone or (combo_count >= 2)

    return is_pii, flags, (name_value, first_value, last_value), keys_with_pii

# Redaction per record
def redact_record(record_dict, flags, name_triple, is_pii):
    name_value, first_value, last_value = name_triple
    redact_full_name = is_pii and flags["has_full_name"]
    redact_email_fields = is_pii and flags["has_email"]
    redact_address_fields = is_pii and flags["has_address"]
    redact_device_ip_fields = is_pii and flags["has_device_or_ip"]

    redacted = {}
    for k, v in list(record_dict.items()):
        new_v = v
        v_str = str(v) if v is not None else ""

        redact_phone = contains_standalone_phone(v, key=k)
        redact_aadhar = contains_aadhar(v)
        redact_passport = contains_passport(v)
        redact_upi = contains_upi(v)
        redact_email_anywhere = RE_EMAIL.search(v_str) is not None
        redact_ip_anywhere = RE_IPV4.search(v_str) is not None

        if k in KEYS_NAME and redact_full_name and isinstance(v, str):
            new_v = mask_name(v)
        elif k in KEYS_FIRST and redact_full_name and isinstance(v, str):
            new_v = v[0] + "X" * (len(v)-1) if isinstance(v, str) and len(v) > 1 else v
        elif k in KEYS_LAST and redact_full_name and isinstance(v, str):
            new_v = v[0] + "X" * (len(v)-1) if isinstance(v, str) and len(v) > 1 else v
        elif k in KEYS_EMAIL and redact_email_fields and isinstance(v, str):
            new_v = mask_email(v)
        elif k in KEYS_ADDRESS and redact_address_fields:
            new_v = mask_address(v)
        elif k in KEYS_CITY and redact_address_fields:
            new_v = "[REDACTED_CITY]"
        elif k in KEYS_STATE and redact_address_fields:
            new_v = "[REDACTED_STATE]"
        elif k in KEYS_PIN and redact_address_fields:
            new_v = "XXXXXX"
        elif k in KEYS_DEVICE and redact_device_ip_fields:
            new_v = mask_device(v)
        elif k in KEYS_IP and redact_device_ip_fields and isinstance(v, str):
            new_v = RE_IPV4.sub(lambda _: "x.x.x.x", v)

        if isinstance(new_v, str):
            new_v = mask_string_value(
                new_v,
                redact_phone=redact_phone,
                redact_aadhar=redact_aadhar,
                redact_passport=redact_passport,
                redact_upi=redact_upi,
                redact_email=redact_email_fields and redact_email_anywhere,
                redact_ip=redact_device_ip_fields and redact_ip_anywhere
            )

        redacted[k] = new_v

    return redacted

# Main
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
        sys.exit(1)

    input_csv = sys.argv[1]
    output_csv = "redacted_output_candidate_full_name.csv"

    with open(input_csv, "r", newline="", encoding="utf-8") as fin, \
         open(output_csv, "w", newline="", encoding="utf-8") as fout:

        reader = csv.DictReader(fin)
        fieldnames = ["record_id", "redacted_data_json", "is_pii"]
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()

        for idx, row in enumerate(reader, start=1):
            record_id = idx
            data_obj = dict(row)

            is_pii, flags, name_triple, _ = evaluate_record(data_obj)
            redacted_obj = redact_record(data_obj, flags, name_triple, is_pii)

            redacted_str = json.dumps(redacted_obj, ensure_ascii=False)

            writer.writerow({
                "record_id": record_id,
                "redacted_data_json": redacted_str,
                "is_pii": str(bool(is_pii))
            })

    print(f"Done. Wrote: {output_csv}")

if __name__ == "__main__":
    main()
