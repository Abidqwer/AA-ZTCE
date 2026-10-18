"""Bounded UTF-8 PII masking; detection is intentionally incomplete.

No raw input or matched substrings leave this module. Non-text input and scanner
errors fail closed. Credit-card detection requires a Luhn-valid 13–19 digit PAN.
"""
import re


class MaskingError(ValueError):
    pass


class DataMasker:
    def __init__(self, max_bytes=1048576):
        if type(max_bytes) is not int or not 1 <= max_bytes <= 1048576:
            raise ValueError('invalid scanner size limit')
        self.max_bytes = max_bytes
        self.patterns = [
            ('SSN', re.compile(r'(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)')),
            ('EMAIL', re.compile(r'(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])', re.I)),
            ('PAN', re.compile(r'(?<!\d)(?:\d[ -]?){12,18}\d(?![ -]?\d)')),
        ]

    @staticmethod
    def luhn(value):
        digits = [int(c) for c in value if c.isdigit() and c.isascii()]
        if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
            return False
        total = 0
        for i, value in enumerate(reversed(digits)):
            if i % 2:
                value *= 2
                if value > 9: value -= 9
            total += value
        return total % 10 == 0

    def mask(self, data):
        if type(data) is not bytes or len(data) > self.max_bytes:
            raise MaskingError('unsupported or oversized protected content')
        try: text = data.decode('utf-8', errors='strict')
        except UnicodeDecodeError: raise MaskingError('protected content is not UTF-8') from None
        counts = {}
        for label, pattern in self.patterns:
            def replace(match):
                if label == 'PAN' and not self.luhn(match.group()): return match.group()
                counts[label] = counts.get(label, 0) + 1
                return '[' + label + '_REDACTED]'
            text = pattern.sub(replace, text)
        return text.encode('utf-8'), counts


def install(domain, config, journal=None):
    """The runtime engine invokes this hook after authorization, before encryption."""
    if set(config) - {'enabled', 'max_bytes'}:
        raise ValueError('unknown DLP configuration field')
    if config.get('enabled', True) is not True:
        if config.get('enabled') is not False: raise ValueError('DLP enabled must be boolean')
        return
    scanner = DataMasker(config.get('max_bytes', 1048576))
    def transform(plaintext, body, grant):
        try: masked, counts = scanner.mask(plaintext)
        except Exception:
            if journal:
                journal.append('data.masking_failed', agent_id=grant['agent'],
                    session_id=grant['sid'], resource_id=body['resource'], outcome='denied',
                    reason_code='dlp_scan_failed', severity=7)
            domain._deny('data masking unavailable; release blocked')
        if counts and journal:
            journal.append('data.masked', agent_id=grant['agent'], session_id=grant['sid'],
                resource_id=body['resource'], reason_code='pii_redacted',
                redaction_count=sum(counts.values()), severity=4)
        return masked
    domain.release_transform = transform
