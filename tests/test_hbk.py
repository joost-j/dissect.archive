from __future__ import annotations

import hashlib
from typing import BinaryIO

import pytest

from dissect.archive.hbk import HBK, InvalidKeyError, MissingKeyError


def test_hbk_volumes(hbk_unencrypted: BinaryIO) -> None:
    hbk = HBK(hbk_unencrypted)

    assert len(hbk.volumes()) == 2
    assert hbk.volumes()[0].name == "@AppConfig"
    assert hbk.volumes()[1].name == "ssd"
    assert hbk.volumes()[0] == hbk.volume("@AppConfig")


def test_hbk_crypted_volumes(hbk_encrypted: BinaryIO) -> None:
    hbk = HBK(hbk_encrypted, password="dissectftw")

    assert len(hbk.volumes()) == 2
    assert hbk.volumes()[0].name == "@AppConfig"
    assert hbk.volumes()[1].name == "ssd"
    assert hbk.volumes()[0] == hbk.volume("@AppConfig")


def test_hbk_crypted_file_wrong_password(hbk_encrypted: BinaryIO) -> None:
    with pytest.raises(expected_exception=InvalidKeyError, match="Wrong password or private key provided"):
        HBK(hbk_encrypted, password="wrongpassword")


def test_hbk_crypted_no_keys_provided(hbk_encrypted: BinaryIO) -> None:
    with pytest.raises(
        expected_exception=MissingKeyError,
        match=r"This HBK file is encrypted, but no password or private key was provided.",
    ):
        HBK(hbk_encrypted)


def test_hbk_file_reading_1(hbk_unencrypted: BinaryIO) -> None:
    hbk = HBK(hbk_unencrypted)
    hbk.use_version(3)

    assert hbk.get("/ssd/dissect_test/some_subfolder/").is_dir()
    file = hbk.get("/ssd/dissect_test/some_subfolder/large_repetitive_data.txt")
    assert not file.is_dir()

    assert file.size == 5_345_280  # ~5.1 MB
    fh = file.open()
    assert fh.read(10) == b"DISSECTFTW"
    assert fh.read(2) == b"DI"
    assert fh.read(5) == b"SSECT"
    assert fh.read(8) == b"FTWDISSE"
    fh.seek(1337)
    assert fh.read(11) == b"FTWDISSECTF"

    # Read it and verify content
    fh.seek(0)
    data = fh.read()
    assert data == b"DISSECTFTW" * 534_528


def test_hbk_unencrypted_versioning(hbk_unencrypted: BinaryIO) -> None:
    hbk = HBK(hbk_unencrypted)
    assert len(hbk.versions) == 4
    # Automatically use highest version
    assert hbk.current_version.id == 4
    with pytest.raises(expected_exception=ValueError, match="Version 0 not found"):
        hbk.use_version(0)  # Error on non-existent version

    # File contents differ between versions
    hbk.use_version(1)
    assert hbk.get("/ssd/dissect_test/Password.txt").open().read() == b"My password is: Summer123!@#"
    hbk.use_version(2)
    assert (
        hbk.get("/ssd/dissect_test/Password.txt").open().read()
        == b"My password is:\r\n\r\nWhoops, I shouldn't have put it there in plaintext."
    )


def test_hbk_file_hashes(hbk_unencrypted: BinaryIO) -> None:
    hbk = HBK(hbk_unencrypted)
    file = hbk.get("/ssd/dissect_test/System32/System32/perfmon.exe")
    assert hashlib.sha1(file.open().read()).hexdigest() == "ae644ffae259ebaf8df6a34d46af05436b8a70d1"
