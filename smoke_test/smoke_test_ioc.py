# paste in a scratch cell / REPL
from agents.ioc_extract import extract_iocs
s = "Failed logins from 203.0.113.45 against https://example.com/login; hash=5d41402abc4b2a76b9719d911017c592; contact secops@example.org"
print([f"{i.type}:{i.value}" for i in extract_iocs(s)])
# expected: ['ip:203.0.113.45','url:https://example.com/login','hash:5d41402abc4b2a76b9719d911017c592','domain:example.com','email:secops@example.org']
