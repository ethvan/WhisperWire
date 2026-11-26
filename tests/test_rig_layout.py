import pytest
from rig.run_layout import create_run_directory, run_directory


def test_run_directory_matches_assignment_layout(tmp_path):
    expected = tmp_path / "L-01" / "A2" / "1"
    assert run_directory(tmp_path, "L-01", "A2", 1) == expected
    assert create_run_directory(tmp_path, "L-01", "A2", 1) == expected
    assert expected.is_dir()


def test_run_directory_rejects_invalid_coordinates(tmp_path):
    with pytest.raises(ValueError):
        run_directory(tmp_path, "../outside", "A0", 0)
    with pytest.raises(ValueError):
        run_directory(tmp_path, "B-01", "A1", 0)
    with pytest.raises(ValueError):
        run_directory(tmp_path, "B-01", "A0", -1)
