from __future__ import annotations

import hashlib
import logging
import zipfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING, BinaryIO

import argon2
from dissect.database import SQLite3
from dissect.util.compression import lz4
from dissect.util.stream import AlignedStream

from dissect.archive.c_hbk import c_hbk
from dissect.archive.exceptions import FileNotFoundError

if TYPE_CHECKING:
    from collections.abc import Iterator

try:
    from Crypto.Hash import SHA512
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    HAS_CRYPTO = True

except ImportError:
    HAS_CRYPTO = False

log = logging.getLogger(__name__)


class InvalidKeyError(Exception):
    pass


class MissingKeyError(Exception):
    pass


def find_rows(
    db_table: SQLite3.table, column_name: str, value: str, single: bool = True
) -> SQLite3.Row | list[SQLite3.Row] | None:
    """
    Generic function to find rows in a SQLite table based on column value.

    Args:
        db_table: SQLite3 table object
        column_name: Name of the column to check
        value: Value to match
        single: If True, return first match or None. If False, return all matches.

    Returns:
        Single row, list of rows, or None/empty list depending on single flag and results.
    """
    if single:
        return next((row for row in db_table.rows() if row.get(column_name) == value), None)
    return [row for row in db_table.rows() if row.get(column_name) == value]


def crypto_pwhash(key: str, salt: str) -> bytes:
    """
    Recreate libsodium's crypto_pwhash functionality using argon2 library.
    """
    return argon2.low_level.hash_secret_raw(
        key.encode(),
        salt=hashlib.md5(salt.encode()).digest(),
        time_cost=4,
        memory_cost=16384,
        parallelism=1,
        hash_len=32,
        type=argon2.low_level.Type.I,
    )


def crypto_box_seed_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """
    Recreate libsodium's crypto_box_seed_keypair functionality using cryptography library.
    """
    sha512 = SHA512.new(seed).digest()

    # Use first 32 bytes as private key and generate the keypair
    private_key = X25519PrivateKey.from_private_bytes(sha512[:32])
    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    return public_key_bytes, sha512[:32]


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

    # def _decrypt(self, data: bytes) -> bytes:
    #     vkey_table = SQLite3(self.zip.open(f"{self.volume.hbk.base}/Pool/vkey.db")).table("vkey")
    #     row = find_rows(vkey_table, "version_id", self.volume.version.id, single=True)

    #     if row:
    #         rsa_vkey = row.get("rsa_vkey")
    #         rsa_vkey_iv = row.get("rsa_vkey_iv")
    #         checksum = row.get("checksum")
    #         ref_count = row.get("ref_count")

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        pools = (x for x in self._chunks_pool_info)

        while length > 0:
            pool = next(pools)

            # Open fresh file handles for each read to avoid state issues
            index_fh = self.volume.hbk.zip.open(f"{self.volume.hbk.base}/Pool/{pool.p1}/{pool.p2}/{pool.pool}.index")
            index_fh.seek(pool.chunk_offset)
            data_info = c_hbk.chunk_pool_data(index_fh)
            chunk_length = data_info.uncompressed_length
            index_fh.close()

            # Here we need to read the chunk
            data_fh = self.volume.hbk.zip.open(f"{self.volume.hbk.base}/Pool/{pool.p1}/{pool.p2}/{pool.pool}.bucket")
            data_fh.seek(data_info.offset)
            data = data_fh.read(data_info.length)
            data_fh.close()

            uncompressed = lz4.decompress(data, uncompressed_size=chunk_length)
            offset_in_block = offset % chunk_length

            read_size = min(length, chunk_length - offset_in_block)
            result.append(uncompressed[offset_in_block : offset_in_block + read_size])

            length -= read_size
            offset += read_size
            if read_size < chunk_length:
                break

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
        version_list_table = self._volume.file_db.table("version_list")
        matching_rows = find_rows(version_list_table, "pname_id_v2", self._row.get("name_id_v2"), single=False)
        for row in matching_rows:
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
        version_list_table = self.file_db.table("version_list")
        matching_rows = find_rows(version_list_table, "pname_id_v2", self.root_name_id_v2, single=False)
        for row in matching_rows:
            yield VolumeEntry(self, row, self.path)


class HBK:
    def __init__(self, fh: BinaryIO, password: str | None = None, private_key: str | None = None):
        self.fh = fh

        # Fetch the main directory name, which will be the first entry in the zip file
        self.zip = zipfile.ZipFile(fh, mode="r")
        self.base = self.zip.filelist[0].filename.rstrip("/")

        # Open some databases that are used multiple times
        self._synobkpinfo_db = SQLite3(self.zip.open(f"{self.base}/synobkpinfo.db")).table("backup_info_tb")

        if self.encrypted:
            if not (password or private_key):
                raise MissingKeyError("This HBK file is encrypted, but no password or private key was provided.")
                # If password or private key is provided, prepare the session key
            if password or private_key:
                try:
                    self.sessionkey = self._prepare_keys(password, private_key)
                except Exception as e:
                    raise InvalidKeyError(e)
        elif not self.encrypted and (password or private_key):
            log.warning("HBK file is not encrypted, but password or private key was provided. Ignoring.")

        self.versions = {
            row.get("id"): Version(row, self)
            for row in SQLite3(self.zip.open(f"{self.base}/Config/version_info.db")).table("version_info").rows()
        }
        self.current_version = self.versions[max(self.versions.keys())]
        log.critical("Version in use: %s", self.current_version)

    def _prepare_keys(self, password: str | None, private_key: str | None) -> bytes:
        if password:
            log.debug("Deriving HBK keypair from provided password.")
            salt_row = find_rows(self._synobkpinfo_db, "info_name", "dataUnique", single=True)

            if not salt_row:
                log.critical("Could not find dataUnique salt in synobkpinfo.db, aborting.")
                exit(1)

            salt_init = salt_row.get("info_value")

            seed = crypto_pwhash(password, salt_init)
            public_key, private_key = crypto_box_seed_keypair(seed)
        elif private_key:
            log.debug("Using provided private key to derive public key.")
            # Private key should be providex as hex
            public_key = (
                X25519PrivateKey.from_private_bytes(private_key)
                .public_key()
                .public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            )

        included_pubkey = self.zip.open(f"{self.base}/Config/public.pem").read()
        if public_key != included_pubkey:
            log.debug("Derived public key: %s", public_key.hex())
            log.debug("Included public key: %s", included_pubkey.hex())
            raise InvalidKeyError("Wrong password or private key provided.")

        log.info("Successfully derived correct decryption key to decrypt file metadata.")

        # encKeys = self.zip.open(f"{self.base}/Config/encKeys").read()

    def use_version(self, version_id: int) -> None:
        if version_id not in self.versions:
            raise ValueError(f"Version {version_id} not found in HBK file")
        self.current_version = self.versions[version_id]

    def volumes(self) -> list[Volume]:
        return list(self.current_version.volumes.values())

    @property
    def encrypted(self) -> bool:
        matching_rows = find_rows(self._synobkpinfo_db, "info_name", "dataEnc", single=True)
        return matching_rows.get("info_value") == "T"

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
