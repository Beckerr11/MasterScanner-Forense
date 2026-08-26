import kernel_rootkit_detector as detector


def test_ssdt_placeholder_does_not_create_a_finding(monkeypatch):
    monkeypatch.setattr(detector.sys, "platform", "win32")
    assert detector.check_ssdt_integrity() == []


def test_hidden_process_placeholder_does_not_create_a_finding(monkeypatch):
    monkeypatch.setattr(detector.sys, "platform", "win32")
    assert detector.check_hidden_processes() == []


def test_kernel_analysis_only_returns_observed_findings(monkeypatch):
    monkeypatch.setattr(detector, "check_unsigned_drivers", lambda: [])
    monkeypatch.setattr(detector, "check_ssdt_integrity", lambda: [])
    monkeypatch.setattr(detector, "check_hidden_processes", lambda: [])

    assert detector.analyze_kernel_for_rootkits() == []
