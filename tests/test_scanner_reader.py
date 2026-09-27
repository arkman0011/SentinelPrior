from pathlib import Path

from sentinelprior.tools.scanner_reader import read_scan_csv


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_valid_sample_is_loaded() -> None:
    result = read_scan_csv(PROJECT_ROOT / "data" / "sample_scan.csv")

    assert len(result.findings) == 5
    assert result.issues == []
    assert result.findings[0].cve_id == "CVE-2021-44228"
    assert result.findings[0].internet_exposed is True


def test_invalid_rows_are_isolated_and_duplicate_removed() -> None:
    result = read_scan_csv(PROJECT_ROOT / "data" / "invalid_and_duplicate_scan.csv")

    assert len(result.findings) == 2
    assert result.duplicates_removed == 1
    assert len(result.issues) == 3
