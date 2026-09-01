# from email import policy
# from email.parser import BytesParser

# file_path = "emails/02_phishing.eml"

# with open(file_path, "rb") as f:
#     msg = BytesParser(policy=policy.default).parse(f)

# print("FROM:", msg.get("From"))
# print("TO:", msg.get("To"))
# print("CC:", msg.get("Cc"))
# print("BCC:", msg.get("Bcc"))
# print("SUBJECT:", msg.get("Subject"))
# print("DATE:", msg.get("Date"))
# print("MESSAGE-ID:", msg.get("Message-ID"))
# print("REPLY-TO:", msg.get("Reply-To"))
# print("RETURN-PATH:", msg.get("Return-Path"))
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from email.header import decode_header
from bs4 import BeautifulSoup
import re


file_path = "emails/02_phishing.eml"


# -----------------------------
# READ EML FILE
# -----------------------------
with open(file_path, "rb") as f:
    msg = BytesParser(policy=policy.default).parse(f)


# -----------------------------
# BASIC HEADERS
# -----------------------------
print("\n========== EMAIL HEADERS ==========")

print("FROM:", msg.get("From"))
print("TO:", msg.get("To"))
print("CC:", msg.get("Cc"))
print("BCC:", msg.get("Bcc"))
print("SUBJECT:", msg.get("Subject"))
print("DATE:", msg.get("Date"))
print("MESSAGE-ID:", msg.get("Message-ID"))
print("REPLY-TO:", msg.get("Reply-To"))
print("RETURN-PATH:", msg.get("Return-Path"))


# -----------------------------
# BODY
# -----------------------------
plain_text = ""
html_text = ""

for part in msg.walk():

    content_type = part.get_content_type()

    if content_type == "text/plain":
        try:
            plain_text += part.get_content()
        except:
            pass

    elif content_type == "text/html":
        try:
            html_text += part.get_content()
        except:
            pass


print("\n========== PLAIN TEXT ==========")
print(plain_text)


# -----------------------------
# LINKS
# -----------------------------
print("\n========== LINKS ==========")

urls = set()

# URLs from plain text
urls.update(
    re.findall(r'https?://[^\s<>"\']+', plain_text)
)

# URLs from HTML href
if html_text:
    soup = BeautifulSoup(html_text, "html.parser")

    for link in soup.find_all("a", href=True):
        urls.add(link["href"])


for url in urls:
    print(url)


# -----------------------------
# ATTACHMENTS
# -----------------------------
print("\n========== ATTACHMENTS ==========")

for part in msg.walk():

    filename = part.get_filename()

    if filename:
        print("Filename:", filename)
        print("Content-Type:", part.get_content_type())

        payload = part.get_payload(decode=True)

        if payload:
            print("Size:", len(payload), "bytes")

        print("--------------------")