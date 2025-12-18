from __future__ import annotations

import logging
import zipfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING, BinaryIO

from dissect.database import SQLite3
from dissect.util.compression import lz4
from dissect.util.stream import AlignedStream

from dissect.archive.c_hbk import c_hbk
from dissect.archive.exceptions import FileNotFoundError

if TYPE_CHECKING:
    from collections.abc import Iterator

try:
    from Crypto.Cipher import AES, ChaCha20_Poly1305
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import unpad

    HAS_CRYPTO = True

except ImportError:
    HAS_CRYPTO = False

log = logging.getLogger(__name__)


class FileStream(AlignedStream):
    def __init__(self, volume: Volume, size: int, path: str, off_virtual_file: int):
        self.volume = volume
        self.path = path
        self.off_virtual_file = off_virtual_file
        # This is probably not how it should be used
        super().__init__(size, align=1)

        # Some preparation in order to _read and _seek properly
        # Now we need to read 56 bytes from the virtual_file.index file
        vfi_fh = self.volume.hbk.zip.open(f"{self.volume.hbk.base}/Config/virtual_file.index/0.idx")
        vfi_fh.seek(self.off_virtual_file)
        virtual_file_entry_data = c_hbk.virtual_file_entry(vfi_fh)
        vfi_fh.close()

        # Now we know where the list of chunks is. Read the virtual file chunk list
        fci_fh = self.volume.hbk.zip.open(
            f"{self.volume.hbk.base}/Config/file_chunk{virtual_file_entry_data.file_chunk_id}.index/0.idx"
        )
        fci_fh.seek(virtual_file_entry_data.chunk_list_offset - 4)
        virtual_file_chunk_list = c_hbk.virtual_file_chunk_list(fci_fh)
        fci_fh.close()

        # Now that we have the chunks, we need to know in which pool they are stored
        indexes = {chunk.index for chunk in virtual_file_chunk_list.chunks}

        chunk_filehandles = {
            index: self.volume.hbk.zip.open(f"{self.volume.hbk.base}/Pool/chunk_index/{index}.idx") for index in indexes
        }

        self._chunks_pool_info = []
        self._unique_pools = set()

        for chunk in virtual_file_chunk_list.chunks:
            # This is not very efficient for now, but we can optimize later
            chi_fh = chunk_filehandles[chunk.index]
            chi_fh.seek(chunk.offset)
            # Read the pool chunk index entry
            chunk_pool_info = c_hbk.chunk_pool_info(chi_fh)
            self._chunks_pool_info.append(chunk_pool_info)
            self._unique_pools.add(f"{chunk_pool_info.p1}/{chunk_pool_info.p2}/{chunk_pool_info.pool}")

        for fh in chunk_filehandles.values():
            fh.close()

        log.debug("File uses chunk pools: %s", self._unique_pools)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        pool_filehandles = {
            pool: (
                self.volume.hbk.zip.open(f"{self.volume.hbk.base}/Pool/{pool}.bucket"),
                self.volume.hbk.zip.open(f"{self.volume.hbk.base}/Pool/{pool}.index"),
            )
            for pool in self._unique_pools
        }

        pools = (x for x in self._chunks_pool_info)

        while length > 0:
            pool = next(pools)

            index_fh = pool_filehandles[f"{pool.p1}/{pool.p2}/{pool.pool}"][1]
            index_fh.seek(pool.chunk_offset)
            data_info = c_hbk.chunk_pool_data(index_fh)
            chunk_length = data_info.uncompressed_length

            # Here we need to read the chunk
            data_fh = pool_filehandles[f"{pool.p1}/{pool.p2}/{pool.pool}"][0]
            data_fh.seek(data_info.offset)
            data = data_fh.read(data_info.length)
            uncompressed = lz4.decompress(data, uncompressed_size=chunk_length)

            offset_in_block = offset % chunk_length

            read_size = min(length, chunk_length - offset_in_block)
            result.append(uncompressed[offset_in_block : offset_in_block + read_size])

            length -= read_size
            offset += read_size
            if read_size < chunk_length:
                break

        # Close all filehandles
        for fh_pair in pool_filehandles.values():
            for fh in fh_pair:
                fh.close()
        return b"".join(result)


class VolumeEntry:
    def __init__(self, volume: Volume = None, row: SQLite3.Row = None, parent: str | None = None):
        self._volume = volume
        self._row = row
        self.name = self._row.get("file_name") if row else ""
        self.path = parent + "/" + self._row.get("file_name") if row and self._volume else parent
        self.size = self._row.get("size") if row else 0

    def open(self) -> BinaryIO:
        return FileStream(self._volume, self.size, self.path, self._row.get("off_virtual_file"))

    def iterdir(self) -> Iterator[VolumeEntry]:
        for row in self._volume.file_db.table("version_list").rows():
            if row.get("pname_id_v2") == self._row.get("name_id_v2"):
                yield VolumeEntry(self._volume, row, self.path)

    def is_dir(self) -> bool:
        if self._row:
            return (self._row.get("mode") & 0xF000) == 0x4000 if self._row else None
        return True

    def is_file(self) -> bool:
        return not self.is_dir()

    def __repr__(self):
        return f"VersionEntry(path={self.path})"


class Version(VolumeEntry):
    def __init__(self, row: SQLite3.Row, hbk: HBK):
        super().__init__()
        self._row = row
        self.id = self._row.get("id")

        self.name = f"v{self.id}"
        self.path = "/"
        self.volumes = {name: Volume(name, self, hbk) for name in self._row.get("share").rstrip(",").split(",")}
        self.timestamp = datetime.fromtimestamp(self._row.get("timestamp"), tz=timezone.utc)

    def volume(self, name: str) -> Volume | None:
        return self.volumes.get(name)

    def is_dir(self) -> bool:
        return True

    def __repr__(self):
        return f"<Version path={self.path} id={self._row.get('id')} timestamp={self.timestamp}>"

    def iterdir(self) -> Iterator[VolumeEntry]:
        yield from self.volumes.values()


class Volume(VolumeEntry):
    def __init__(self, name: str, version: Version, hbk: HBK):
        super().__init__()
        self.hbk = hbk
        self.name = name
        self.version = version
        self.file_db = SQLite3(self.hbk.zip.open(f"{self.hbk.base}/Config/@Share/{self.name}/{self.version.id}.db"))

        # Stuff for the DirItem base class
        self.root_name_id_v2 = None
        self.path = self.version.path + self.name

        # Search for the identifier of the root directory
        for row in self.file_db.table("version_list").rows():
            pname_id_v2 = row.get("pname_id_v2")
            if pname_id_v2[:4] == pname_id_v2[4:8]:
                self.root_name_id_v2 = pname_id_v2
                break

    def __repr__(self) -> str:
        return f"<Volume path={self.path} id={(self.root_name_id_v2.hex())}>"

    def is_dir(self) -> bool:
        return True

    def iterdir(self) -> Iterator[VolumeEntry]:
        for row in self.file_db.table("version_list").rows():
            if row.get("pname_id_v2") == self.root_name_id_v2:
                yield VolumeEntry(self, row, self.path)


class HBK:
    def __init__(self, fh: BinaryIO, version: int = -1, key: bytes | None = None):
        self.fh = fh
        # Fetch the main directory name, which will be the first entry in the zip file
        self.zip = zipfile.ZipFile(fh, mode="r")
        self.base = self.zip.filelist.pop(0).filename.rstrip("/")
        self.key = key
        if self.key:
            log.critical(f"Using provided HBK decryption key: {self.key}")
        log.critical("HBK base directory: %s", self.base)

        self.versions = {
            row.get("id"): Version(row, self)
            for row in SQLite3(self.zip.open(f"{self.base}/Config/version_info.db")).table("version_info").rows()
        }
        self.current_version = self.versions[max(self.versions.keys())]
        log.info("Version in use: %s", self.current_version)

    def decrypt_b64(self, b64str: str) -> bytes:
        if not self.key:
            raise ValueError("No decryption key available for HBK decryption")
        # TODO check what kind of encryption is used
        raise NotImplementedError("HBK decryption not yet implemented")

    def use_version(self, version_id: int) -> None:
        if version_id not in self.versions:
            raise ValueError(f"Version {version_id} not found in HBK file")
        self.current_version = self.versions[version_id]

    def volumes(self) -> list[Volume]:
        return list(self.current_version.volumes.values())

    def volume(self, name: str) -> Volume | None:
        return self.current_version.volume(name)

    def get(self, path: str, item: VolumeEntry | None = None) -> VolumeEntry:
        """Get a directory item from the VBK file."""
        item = item or self.current_version

        for part in path.split("/"):
            if not part:
                continue

            for entry in item.iterdir():
                if entry.name == part:
                    item = entry
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return item
