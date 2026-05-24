import re
import json
import os

# Build absolute paths so the script works from any directory
BASE_DIR    = os.path.dirname(os.path.abspath("alu-regex-data-extraction_zotyall"))
INPUT_FILE  = os.path.join(BASE_DIR, "input", "raw-text.txt")
OUTPUT_FILE = os.path.join(BASE_DIR, "output", "sample-output.json")

# Read input file
with open(INPUT_FILE, "r") as f:
    text = f.read()

# --------------------------------------------------
# SECURITY CHECK
# Scan for dangerous patterns before anything else.
# Threats are logged but never executed.
# --------------------------------------------------
threats = []

if re.search(r"<script>", text):
    threats.append("XSS script tag detected")
if re.search(r"javascript:", text):
    threats.append("Javascript injection detected")
if re.search(r"DROP TABLE", text):
    threats.append("SQL injection detected")
if re.search(r"\.\./", text):
    threats.append("Path traversal detected")

if threats:
    print("WARNING - Malicious content found:")
    for t in threats:
        print("  -", t)
else:
    print("Security check passed.")

# --------------------------------------------------
# EMAILS
# Pattern: letters/digits before @, domain, dot, extension
# Sorted into ALU official, alumni, SI, and external
# --------------------------------------------------
all_emails = re.findall(r"\w[\w.]+@\w[\w.]+\.\w+", text)

alu_official = []
alu_alumni   = []
alu_si       = []
external     = []

for email in all_emails:
    if re.search(r"@alumni\.alueducation\.com$", email):
        alu_alumni.append(email)
    elif re.search(r"@si\.alueducation\.com$", email):
        alu_si.append(email)
    elif re.search(r"@alueducation\.com$", email):
        alu_official.append(email)
    else:
        external.append(email)

# --------------------------------------------------
# URLs
# Pattern: http or https then :// then non-space chars
# --------------------------------------------------
urls = re.findall(r"https?://\S+", text)

# --------------------------------------------------
# PHONE NUMBERS
# Pattern: starts with + or digit, allows spaces/dashes/brackets
# Only kept if total digits are between 7 and 15
# --------------------------------------------------
phones = re.findall(r"[\+\d][\d \-\(\)]{7,20}", text)

clean_phones = []
for p in phones:
    digits = re.sub(r"\D", "", p)
    if 7 <= len(digits) <= 15:
        clean_phones.append(p.strip())

# --------------------------------------------------
# CREDIT CARDS
# Visa/MC/Discover: 4-4-4-4 format
# Amex: 4-6-5 format
# Masked in output — only last 4 digits shown
# --------------------------------------------------
cards = re.findall(r"\d{4} \d{4} \d{4} \d{4}", text)
amex  = re.findall(r"\d{4} \d{6} \d{5}", text)
all_cards = cards + amex

def mask_card(card):
    digits = re.sub(r"\D", "", card)
    return "** ** ** " + digits[-4:]

# --------------------------------------------------
# TIMES
# 12-hour: 8:00 AM, 12:30 PM
# 24-hour: 23:45, 17:00
# --------------------------------------------------
times_12 = re.findall(r"\d{1,2}:\d{2}\s?[APap][Mm]", text)
times_24 = re.findall(r"\b[012]\d:[0-5]\d\b", text)

# --------------------------------------------------
# HTML TAGS
# Pattern: anything between < and >
# --------------------------------------------------
tags = re.findall(r"<[^>]+>", text)

# --------------------------------------------------
# HASHTAGS
# Pattern: # followed by word characters
# --------------------------------------------------
hashtags = re.findall(r"#\w+", text)

# --------------------------------------------------
# CURRENCY
# Pattern: $ or € then digits, RWF handled separately
# --------------------------------------------------
currency = re.findall(r"[\$€]\d+\.?\d*", text)
rwf      = re.findall(r"RWF\s\d+", text)
all_currency = currency + rwf

# --------------------------------------------------
# BUILD AND SAVE RESULTS
# --------------------------------------------------
results = {
    "security": {
        "threats_found": threats
    },
    "emails": {
        "alu_official": alu_official,
        "alu_alumni":   alu_alumni,
        "alu_si":       alu_si,
        "external":     external
    },
    "urls":          urls,
    "phone_numbers": clean_phones,
    "credit_cards":  [mask_card(c) for c in all_cards],
    "times": {
        "12_hour": times_12,
        "24_hour": times_24
    },
    "html_tags": tags,
    "hashtags":  hashtags,
    "currency":  all_currency
}

# Print summary to console
print("\n===== RESULTS =====")
print("Emails          :", len(all_emails))
print("  ALU Official  :", len(alu_official))
print("  ALU Alumni    :", len(alu_alumni))
print("  ALU SI        :", len(alu_si))
print("  External      :", len(external))
print("URLs            :", len(urls))
print("Phone numbers   :", len(clean_phones))
print("Credit cards    :", len(all_cards))
print("Times (12-hour) :", len(times_12))
print("Times (24-hour) :", len(times_24))
print("HTML tags       :", len(tags))
print("Hashtags        :", len(hashtags))
print("Currency        :", len(all_currency))
print("===================")

# Save to JSON
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
with open(OUTPUT_FILE, "w") as f:
    json.dump(results, f, indent=2)

print("\nSaved to output/sample-output.json")