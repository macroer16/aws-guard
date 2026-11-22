from aws_guard.ai import anonymise
from aws_guard.cli import main
from aws_guard.models import Finding, ScanResult, Severity
from aws_guard.scoring import score, summary


def f(sev, cost=None, res="r", cat="security"):
    return Finding("x", None, "s3", sev, res, "eu-west-2", "Thing is wrong", "Fix it", cat, cost)


def test_score_penalties():
    assert score([]) == 100
    assert score([f(Severity.CRITICAL), f(Severity.HIGH), f(Severity.MEDIUM), f(Severity.LOW)]) == 65
    assert score([f(Severity.CRITICAL)] * 10) == 0
    assert score([f(Severity.LOW, cat="cost")]) == 100  # cost findings don't lower the security score


def test_sorted_worst_first_then_cost():
    r = ScanResult("eu-west-2", None, [f(Severity.LOW, 5), f(Severity.CRITICAL), f(Severity.LOW, 50)])
    assert [x.severity for x in r.sorted()] == [Severity.CRITICAL, Severity.LOW, Severity.LOW]
    assert r.sorted()[1].monthly_cost == 50


def test_summary_mentions_waste():
    assert "$55.00/month" in summary([f(Severity.LOW, 5, cat="cost"), f(Severity.LOW, 50, cat="cost")])


def test_anonymise_hides_resource_names():
    out = anonymise(
        [
            f(Severity.HIGH, res="secret-bucket"),
            f(Severity.LOW, res="secret-bucket"),
            f(Severity.LOW, res="i-0abc"),
        ]
    )
    text = str(out)
    assert "secret-bucket" not in text and "i-0abc" not in text
    assert [o["resource"] for o in out] == ["resource-1", "resource-1", "resource-2"]


def test_demo_end_to_end(tmp_path):
    code = main(["--demo", "--output", str(tmp_path), "--fail-on", "critical"])
    assert code == 1  # the demo account has critical issues
    html = (tmp_path / "report.html").read_text()
    assert "acme-public-assets" in html and "/ 100" in html
    assert (tmp_path / "findings.json").exists()
