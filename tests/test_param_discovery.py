from src.pyauto.param_discovery import discover


def test_finds_real_param_zero_fp():
    def mock(params):
        return (200, "LONG SECRET BODY " * 4) if "secret" in params else (200, "base")
    names = [f"p{i}" for i in range(150)] + ["secret"]
    assert discover(mock, names) == ["secret"]
    assert discover(lambda p: (200, "static"), [f"n{i}" for i in range(80)]) == []   # 0 FP
