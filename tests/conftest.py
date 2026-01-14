from __future__ import annotations

import gzip
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def open_file(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with absolute_path(name).open(mode) as f:
        yield f


def open_file_gz(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(name), mode) as f:
        yield f


@pytest.fixture
def basic_wim_4k() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/basic4k.wim.gz")


@pytest.fixture
def basic_wim_8k() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/basic8k.wim.gz")


@pytest.fixture
def basic_wim_16k() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/basic16k.wim.gz")


@pytest.fixture
def basic_wim_32k() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/basic32k.wim.gz")


@pytest.fixture
def basic_vma() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/test.vma.gz")


@pytest.fixture
def vbk9() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/test9.vbk.gz")


@pytest.fixture
def vbk13() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/test13.vbk.gz")


@pytest.fixture
def hbk_encrypted() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/dissect_test_encrypted.hbk.gz")


@pytest.fixture
def hbk_unencrypted() -> Iterator[BinaryIO]:
    yield from open_file("_data/dissect_backup_test_task.hbk")
