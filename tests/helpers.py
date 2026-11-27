import base64


def tag_encode(text):
    return "".join(chr(0xE0000 + ord(ch)) for ch in text)


def cp(code_point):
    return chr(code_point)


def rot13(text):
    output = []
    for ch in text:
        code = ord(ch)
        if 65 <= code <= 90:
            output.append(chr(((code - 65 + 13) % 26) + 65))
        elif 97 <= code <= 122:
            output.append(chr(((code - 97 + 13) % 26) + 97))
        else:
            output.append(ch)
    return "".join(output)


def hex_encode(text):
    return text.encode("utf-8").hex()


def base64_encode(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def url_encode_bytes(text):
    return "".join("%" + byte.to_bytes(1, "big").hex().upper() for byte in text.encode("utf-8"))


def finding_ids(result):
    items = result if isinstance(result, (list, tuple)) else result.findings
    return [finding.id for finding in items]


def has_finding(result, rule_id):
    return rule_id in finding_ids(result)


def deterministic_string(seed, length):
    state = seed & 0xFFFFFFFF
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;:_-"
    output = []
    for _ in range(length):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        output.append(alphabet[state % len(alphabet)])
    return "".join(output)


def add_cases(cls, prefix, values, body):
    for index, value in enumerate(values):
        def test_method(self, value=value):
            body(self, value)
        test_method.__name__ = "test_%s_%03d" % (prefix, index)
        setattr(cls, test_method.__name__, test_method)
