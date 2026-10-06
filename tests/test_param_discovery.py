from src.pyauto.param_discovery import discover


def test_finds_real_param_zero_fp():
    def mock(params):
        return (200, "LONG SECRET BODY " * 4) if "secret" in params else (200, "base")
    names = [f"p{i}" for i in range(150)] + ["secret"]
    assert discover(mock, names) == ["secret"]
    assert discover(lambda p: (200, "static"), [f"n{i}" for i in range(80)]) == []   # 0 FP


def test_parallel_map_runs_all_and_swallows_errors():
    from src.pyauto.param_discovery import parallel_map
    out = parallel_map(lambda x: x * 2, [1, 2, 3, 4], workers=4)
    assert sorted(out) == [2, 4, 6, 8]
    def boom(x):
        if x == 2:
            raise ValueError("x")
        return x
    res = parallel_map(boom, [1, 2, 3], workers=3)
    assert None in res and 1 in res and 3 in res          # one item errored -> None, others fine


def test_throttle_is_thread_safe_rate_cap():
    import threading, time
    from benchmarks.nodegoat import exploit as E
    E._MIN_INTERVAL = 0.02
    E._last_request = 0.0
    n = 20
    t = time.time()
    threads = [threading.Thread(target=E._throttle) for _ in range(n)]
    for th in threads: th.start()
    for th in threads: th.join()
    # n calls paced >= MIN_INTERVAL apart under a lock => total >= (n-1)*interval, regardless of threads
    assert time.time() - t >= (n - 1) * 0.02 * 0.8
