from src.pyauto.repair import _attack_repr, _prompt


def test_attack_repr_differential():
    pov = {"differential": {"true_request": {"method": "GET", "path": "/x?id=1 OR 1=1"}}}
    assert _attack_repr(pov) == "GET /x?id=1 OR 1=1"


def test_attack_repr_marker_with_body():
    pov = {"method": "POST", "path": "/p", "body": {"q": ";id"}}
    assert _attack_repr(pov) == "POST /p body={'q': ';id'}"


def test_prompt_includes_the_attack():
    f = {"klass": "injection", "cwe": "CWE-89", "function": "h"}
    pov = {"method": "GET", "path": "/x?id=1'"}
    p = _prompt(f, "def h(): ...", pov)
    assert "/x?id=1'" in p and "MUST make it stop" in p
    # no pov -> no attack line, still valid
    assert "exploit our oracle replays" not in _prompt(f, "def h(): ...")
