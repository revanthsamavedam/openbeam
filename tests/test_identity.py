import pytest

from openbeam import identity as I


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENBEAM_HOME", str(tmp_path / "ob"))
    return tmp_path / "ob"


def test_identity_stable(home):
    kf1, cf1 = I.load_or_create_identity()
    fp1 = I.fingerprint()
    kf2, cf2 = I.load_or_create_identity()
    assert (kf1, cf1) == (kf2, cf2)
    assert I.fingerprint() == fp1
    assert len(fp1) == 64
    # key file is private
    import os
    assert oct(os.stat(kf1).st_mode & 0o777) == "0o600"


def test_device_id_stable(home):
    assert I.device_id() == I.device_id()


def test_trust_store_roundtrip(home):
    ts = I.TrustStore()
    assert not ts.is_trusted("ab" * 32)
    ts.trust("ab" * 32, "laptop")
    assert ts.is_trusted("ab" * 32)
    assert ts.name_of("ab" * 32) == "laptop"
    ts2 = I.TrustStore()
    assert ts2.is_trusted("ab" * 32)
    assert ts.untrust("ab" * 32)
    assert not ts.is_trusted("ab" * 32)


def test_trust_uri_roundtrip(home):
    uri = I.trust_uri("My Mac", "abc123", "de" * 32)
    info = I.parse_trust_uri(uri)
    assert info["fp"] == "de" * 32
    assert info["name"] == "My Mac"
    assert info["id"] == "abc123"
    bare = I.parse_trust_uri("de" * 32)
    assert bare["fp"] == "de" * 32
