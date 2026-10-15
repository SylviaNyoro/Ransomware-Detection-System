from src.feature_engineering.features import EventType, FileEvent, compute_features

COMMON_EXT = [".txt", ".docx", ".pdf"]


def test_benign_activity_low_signal():
    """A user editing one document should look nothing like ransomware."""
    events = [
        FileEvent(path="/home/user/docs/report.docx", event_type=EventType.OPENED),
        FileEvent(path="/home/user/docs/report.docx", event_type=EventType.MODIFIED),
    ]
    fv = compute_features(events, COMMON_EXT)
    assert fv.modification_frequency == 1
    assert fv.extension_change_rate == 0
    assert fv.file_access_breadth == 1


def test_ransomware_like_activity_high_signal():
    """Rapid, broad renaming to an unusual extension should score high on all 3."""
    events = [
        FileEvent(
            path=f"/home/user/docs/file{i}.docx",
            event_type=EventType.RENAMED,
            dest_path=f"/home/user/{'docs' if i % 2 == 0 else 'photos'}/file{i}.locked",
        )
        for i in range(6)
    ]
    fv = compute_features(events, COMMON_EXT)
    assert fv.extension_change_rate == 1  # only one unusual extension: .locked
    assert fv.file_access_breadth == 2  # docs + photos


def test_empty_window():
    fv = compute_features([], COMMON_EXT)
    assert fv.as_dict() == {
        "modification_frequency": 0,
        "extension_change_rate": 0,
        "file_access_breadth": 0,
    }
