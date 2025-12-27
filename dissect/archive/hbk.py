from __future__ import annotations

import base64
import hashlib
import logging
import zipfile
from datetime import datetime, timezone
from enum import Enum
from functools import cached_property
from typing import TYPE_CHECKING, BinaryIO

import argon2
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from dissect.database import SQLite3
from dissect.util.compression import lz4
from dissect.util.stream import AlignedStream
from nacl.public import PrivateKey, SealedBox

from dissect.archive.c_hbk import c_hbk
from dissect.archive.exceptions import FileNotFoundError

if TYPE_CHECKING:
    from collections.abc import Iterator


log = logging.getLogger(__name__)


class Constants(Enum):
    CHECKSUM = "8Llx6OSaDPzbwCkjG8eYc64GZGMIlMXm"
    FILENAME = "kkE7sRZRvnbVlJFofhD7WCXumXBGyzki"


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
    sha512 = hashlib.sha512(seed).digest()
    private_key = PrivateKey(sha512[:32])
    public_key = private_key.public_key
    return bytes(public_key), sha512[:32]


def crypto_box_seal_open(ciphertext: bytes, private_key: bytes) -> bytes:
    priv_key = PrivateKey(private_key)
    sealed_box = SealedBox(priv_key)
    return sealed_box.decrypt(ciphertext)


class FileStream(AlignedStream):
    def __init__(self, volume: Volume, size: int, path: str, off_virtual_file: int):
        self.volume = volume
        self.path = path
        self.off_virtual_file = off_virtual_file

        log.debug("FileStream init: path=%s, size=%d, off_virtual_file=%d", path, size, off_virtual_file)

        # This is probably not how it should be used
        super().__init__(size, align=1)

        # Some preparation in order to _read and _seek properly
        # Now we need to read 56 bytes from the virtual_file.index file
        vfi_fh = self.volume.hbk.zip.open(f"{self.volume.hbk.base}/Config/virtual_file.index/0.idx")
        vfi_fh.seek(self.off_virtual_file)
        virtual_file_entry_data = c_hbk.virtual_file_entry(vfi_fh)
        vfi_fh.close()
        log.debug(
            "Virtual file entry: file_chunk_id=%d, chunk_list_offset=%d",
            virtual_file_entry_data.file_chunk_id,
            virtual_file_entry_data.chunk_list_offset,
        )

        # Now we know where the list of chunks is. Read the virtual file chunk list
        fci_fh = self.volume.hbk.zip.open(
            f"{self.volume.hbk.base}/Config/file_chunk{virtual_file_entry_data.file_chunk_id}.index/0.idx"
        )
        fci_fh.seek(virtual_file_entry_data.chunk_list_offset - 4)
        virtual_file_chunk_list = c_hbk.virtual_file_chunk_list(fci_fh)
        fci_fh.close()
        log.debug("Found %d chunks for file %s", len(virtual_file_chunk_list.chunks), self.path)

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

        log.debug(
            "FileStream init complete: %d chunks mapped to %d unique pools",
            len(self._chunks_pool_info),
            len(self._unique_pools),
        )

    def _read(self, offset: int, length: int) -> bytes:
        log.debug("_read called: offset=%d, length=%d for file %s", offset, length, self.path)
        result = []

        pools = (x for x in self._chunks_pool_info)
        chunk_idx = 0

        while length > 0:
            pool = next(pools)
            log.debug(
                "Processing chunk %d: pool=%s/%s/%s, chunk_offset=%d",
                chunk_idx,
                pool.p1,
                pool.p2,
                pool.pool,
                pool.chunk_offset,
            )

            # Read the chunk pool data index to get offset and lengths
            index_fh = self.volume.hbk.zip.open(f"{self.volume.hbk.base}/Pool/{pool.p1}/{pool.p2}/{pool.pool}.index")
            index_fh.seek(pool.chunk_offset)
            data_info = c_hbk.chunk_pool_data(index_fh)
            index_fh.close()
            log.debug(
                "Chunk data: offset=%d, length=%d, uncompressed_length=%d",
                data_info.offset,
                data_info.length,
                data_info.uncompressed_length,
            )

            # Here we need to read the actual chunk data from a bucket file
            data_fh = self.volume.hbk.zip.open(f"{self.volume.hbk.base}/Pool/{pool.p1}/{pool.p2}/{pool.pool}.bucket")
            data_fh.seek(data_info.offset)
            data = data_fh.read(data_info.length)
            data_fh.close()

            if self.volume.hbk.encrypted:
                log.debug("File encrypted: %s", self.volume.hbk.encrypted)
                # This shouldn't be a for loop, but can't yet find where the encryption version is stored
                for version, aes_keys in self.volume.version_keys.items():
                    log.debug("Trying to decrypt chunk with version keys of version %d", version)
                    try:
                        data = AES.new(aes_keys["vkey"], AES.MODE_CBC, aes_keys["vkey_iv"]).decrypt(data)
                        data = unpad(data, AES.block_size)
                        uncompressed = lz4.decompress(data, uncompressed_size=data_info.uncompressed_length)
                        log.debug("Decryption and decompression successful with version %d keys", version)
                        break
                    except Exception as e:
                        log.debug("Decryption with version %d keys failed: %s", version, e)
                        continue

            else:
                uncompressed = lz4.decompress(data, uncompressed_size=data_info.uncompressed_length)
            offset_in_block = offset % data_info.uncompressed_length

            read_size = min(length, data_info.uncompressed_length - offset_in_block)
            log.debug("Reading from chunk %d: offset_in_block=%d, read_size=%d", chunk_idx, offset_in_block, read_size)
            result.append(uncompressed[offset_in_block : offset_in_block + read_size])

            length -= read_size
            offset += read_size
            chunk_idx += 1
            if read_size < data_info.uncompressed_length:
                break

        return b"".join(result)


class VolumeEntry:
    def __init__(self, volume: Volume = None, row: SQLite3.Row = None, parent: str | None = None):
        self._volume = volume
        self._row = row
        self.name = self._row.get("file_name") if row else ""
        if self._volume and self._row and self._volume.hbk.encrypted:
            self.name = self._volume.hbk._decrypt_filename(self.name)
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

        if self.hbk.encrypted:
            self.version_keys = self._prepare_version_keys()

        # Search for the identifier of the root directory
        for row in self.file_db.table("version_list").rows():
            pname_id_v2 = row.get("pname_id_v2")
            if pname_id_v2[:4] == pname_id_v2[4:8]:
                self.root_name_id_v2 = pname_id_v2
                break

    def _prepare_version_keys(self) -> None:
        # Even though we browse the HBK file in only one version,
        # files are encrypted with version-specific keys so prepare them here.
        vkeys = {}
        vkey_table = SQLite3(self.hbk.zip.open(f"{self.hbk.base}/Pool/vkey.db")).table("vkey")
        for row in vkey_table.rows():
            version_id = int(row.get("version_id"))
            rsa_vkey = row.get("rsa_vkey")
            rsa_vkey_iv = row.get("rsa_vkey_iv")
            checksum = row.get("checksum")

            checksum_data = rsa_vkey + Constants.CHECKSUM.value.encode("utf-8") + rsa_vkey_iv
            calculated_checksum = hashlib.md5(checksum_data).digest()

            if calculated_checksum != checksum:
                log.warning("Version key checksum mismatch for version %d, skipping", version_id)
                continue

            log.debug("Decrypting version key for version %d", version_id)
            log.debug("Encrypted rsa_vkey: %s", rsa_vkey.hex())
            log.debug("Length of rsa_vkey: %d", len(rsa_vkey))
            log.debug("Our private key: %s", self.hbk.privkey.hex())
            log.debug("Our public key: %s", self.hbk.pubkey.hex())
            decrypted_vkey = crypto_box_seal_open(rsa_vkey, self.hbk.privkey)
            log.debug("Decrypted rsa_vkey: %s", decrypted_vkey.hex())
            decrypted_vkey_iv = crypto_box_seal_open(rsa_vkey_iv, self.hbk.privkey)
            log.debug("Decrypted rsa_vkey_iv: %s", decrypted_vkey_iv.hex())
            vkeys[version_id] = {"vkey": decrypted_vkey, "vkey_iv": decrypted_vkey_iv}

        return vkeys

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
                    self.privkey, self.pubkey = self._prepare_keys(password, private_key)
                except Exception as e:
                    raise InvalidKeyError(e)
        elif not self.encrypted and (password or private_key):
            log.warning("HBK file is not encrypted, but password or private key was provided. Ignoring.")

        self.versions = {
            row.get("id"): Version(row, self)
            for row in SQLite3(self.zip.open(f"{self.base}/Config/version_info.db")).table("version_info").rows()
        }
        self.current_version = self.versions[max(self.versions.keys())]
        log.debug("Version in use: %s", self.current_version)

    def _prepare_keys(self, password: str | None, private_key: str | None) -> bytes:
        if password:
            log.debug("Deriving HBK keypair from provided password.")
            seed = crypto_pwhash(password, self.unikey)
            public_key, private_key = crypto_box_seed_keypair(seed)
        elif private_key:
            log.debug("Using provided private key to derive public key.")
            public_key = bytes(PrivateKey(private_key).public_key)

        included_pubkey = self.zip.open(f"{self.base}/Config/public.pem").read()
        if public_key != included_pubkey:
            log.debug("Derived public key: %s", public_key.hex())
            log.debug("Included public key: %s", included_pubkey.hex())
            raise InvalidKeyError("Wrong password or private key provided.")

        log.info("Successfully derived correct decryption key to decrypt file metadata.")
        log.debug("Private key: %s", private_key.hex())
        log.debug("Public key: %s", public_key.hex())
        return private_key, public_key

        # encKeys = self.zip.open(f"{self.base}/Config/encKeys").read()

    def _decrypt_filename(self, b64_name: str) -> str:
        # Create a sha256 hash of the private key

        private_key = self.privkey + self.unikey.encode("utf-8")
        key = hashlib.sha256(private_key).digest()

        combined = self.unikey + Constants.FILENAME.value
        iv = hashlib.md5(combined.encode("utf-8")).digest()
        log.debug("Base64 filename: %s", b64_name)
        ciphertext = base64.urlsafe_b64decode(b64_name)
        plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
        unpadded_plaintext = unpad(plaintext, AES.block_size)

        return unpadded_plaintext.decode("utf-8")

    def use_version(self, version_id: int) -> None:
        if version_id not in self.versions:
            raise ValueError(f"Version {version_id} not found in HBK file")
        self.current_version = self.versions[version_id]

    def volumes(self) -> list[Volume]:
        return list(self.current_version.volumes.values())

    @cached_property
    def encrypted(self) -> bool:
        matching_rows = find_rows(self._synobkpinfo_db, "info_name", "dataEnc", single=True)
        return matching_rows.get("info_value") == "T"

    @cached_property
    def unikey(self) -> str:
        unikey_row = find_rows(self._synobkpinfo_db, "info_name", "dataUnique", single=True)
        return unikey_row.get("info_value")

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
