from modules.password import evaluate, hash_password


def test_evaluate_ok():
    level, message = evaluate(0)
    assert level == "OK"

def test_evaluate_attention_one():
    level, message = evaluate(1)
    assert level == "ATTENTION"

def test_evaluate_risk():
    level, message = evaluate(100)
    assert level == "RISK"

def test_evaluate_attention_ninetynine():
    level, message = evaluate(99)
    assert level == "ATTENTION"


def test_hash_password_known_value():
    assert hash_password("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"