from enum import Enum


class IoCType(str, Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    EMAIL_ADDRESS = "email_address"
    CVE = "cve"
    MUTEX = "mutex"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    USER_AGENT = "user_agent"
    CERTIFICATE = "certificate"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TLP(str, Enum):
    WHITE = "white"
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class Confidence(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERIFIED = "verified"
