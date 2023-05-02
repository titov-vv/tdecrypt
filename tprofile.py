import os
import logging
import struct
from hashlib import md5, sha1, sha256, sha512, pbkdf2_hmac
from Crypto.Cipher import AES
from PySide6.QtCore import QDataStream, QByteArray, QBuffer, QIODevice, QDateTime
import tgcrypto


KEY_FILE = "key_data"
MAP_FILE = "map"
SUFFIX = 's'
DECRYPTED_SUFFIX = ".dec"
OUT_DIR = "OUT"
BLOCK_SIZE = 16

# Telegram Local Storage Keys
class LSK:
    lskUserMap = 0x00
    lskDraft = 0x01   #  data: PeerId peer
    lskDraftPosition = 0x02   #  data: PeerId peer
    lskLegacyImages = 0x03   #  legacy
    lskLocations = 0x04   #  no data
    lskLegacyStickerImages = 0x05   #  legacy
    lskLegacyAudios = 0x06   #  legacy
    lskRecentStickersOld = 0x07   #  no data
    lskBackgroundOldOld = 0x08   #  no data
    lskUserSettings = 0x09   #  no data
    lskRecentHashtagsAndBots = 0x0a   #  no data
    lskStickersOld = 0x0b   #  no data
    lskSavedPeersOld = 0x0c   #  no data
    lskReportSpamStatusesOld = 0x0d   #  no data
    lskSavedGifsOld = 0x0e   #  no data
    lskSavedGifs = 0x0f   #  no data
    lskStickersKeys = 0x10   #  no data
    lskTrustedBots = 0x11   #  no data
    lskFavedStickers = 0x12   #  no data
    lskExportSettings = 0x13   #  no data
    lskBackgroundOld = 0x14   #  no data
    lskSelfSerialized = 0x15   #  serialized self
    lskMasksKeys = 0x16   #  no data
    lskCustomEmojiKeys = 0x17   #  no data


# Class that handles local Telegram profile data
# path - path to the folder where profile is located
# profile - string with profile folder name
class TelegramProfile:
    def __init__(self, path: str, profile: str):
        self._path = path
        self._profile = profile
        self._localKey = None
        self._key = None

    # Function returns raw content of TDF-file and its version
    def __readTDF(self, filename: str) -> (bytes, int):
        with open(filename, "rb") as file:
            magic = struct.unpack('4s', file.read(4))[0]
            if magic != b'TDF$':
                raise ValueError(f"Wrong magic: {magic}")
            version = struct.unpack('<i', file.read(4))[0]
            data = file.read()
            md5_sum = data[-16:]
            data = data[:-16]
            md5_buffer = data + struct.pack('<i', len(data)) + struct.pack('<i', version) + magic
            md5_verify = md5(md5_buffer).digest()
            assert md5_verify == md5_sum, "MD5 doesn't match"
            return data, version

    # Data contains serialized streams. This function returns a list of QDataStream objects loaded from data.
    def __readStreams(self, data: bytes) -> list:
        result = []
        binary_data = QByteArray(data)
        stream = QDataStream(binary_data)
        while not stream.atEnd():
            x = QByteArray()
            stream >> x
            result.append(x)
        return result

    # Calculate and store local key from given salt (password is assumed to be '')
    def __CreateLocalKey(self, salt: bytes):
        m = sha512(salt)  # b'' - because password len = 0
        m.update(b'')
        m.update(salt)
        key_hash = m.digest()
        self._localKey = pbkdf2_hmac('sha512', key_hash, salt, 1, dklen=256)

    # Helper function for __DecryptLocal that does actual AES decription
    def __aesDecryptLocal(self, src: bytes, authKey :bytes, key128: bytes) -> bytes:
        x = 8
        data_a = key128 + authKey[x:x+32]
        sha1_a = sha1(data_a).digest()
        data_b = authKey[x+32:x+48] + key128 + authKey[x+48:x+64]
        sha1_b = sha1(data_b).digest()
        data_c = authKey[x+64:x+96] + key128
        sha1_c = sha1(data_c).digest()
        data_d = key128 + authKey[x+96:x+128]
        sha1_d = sha1(data_d).digest()
        key = sha1_a[:8] + sha1_b[8:20] + sha1_c[4:16]
        iv = sha1_a[8:20] + sha1_b[:8] + sha1_c[16:20] + sha1_d[:8]
        aes_key = key[:32]
        aes_iv = iv[:32]
        dst = tgcrypto.ige256_decrypt(src, aes_key, aes_iv)
        return dst

    # Decrypts encrypted bytes and return decrypted result as a dict that contains decrypted data in form of:
    # 'data' - QByteArray, 'buffer' = QBuffer, 'stream' = QDataStream
    def __DecryptLocal(self, encrypted: bytes, key: bytes) -> dict:
        result = {}
        decrypted = self.__aesDecryptLocal(encrypted[16:], key, encrypted[:16])
        dataLen =  struct.unpack('i', decrypted[:4])[0]
        result['data'] = QByteArray(decrypted[:dataLen])
        result['buffer'] = QBuffer(result['data'])
        result['buffer'].open(QIODevice.ReadOnly)
        result['buffer'].seek(4)  # skip  len
        result['stream'] = QDataStream(result['buffer'])
        result['stream'].setVersion(QDataStream.Qt_5_1)
        return result

    # Decrypts an encryption key
    def __DecryptKey(self, encrypted_key: bytes):
        keyData = self.__DecryptLocal(encrypted_key, self._localKey)
        self._key = keyData['stream'].readRawData(256)

    # Reads Telegram map data from the stream and returns it in form of a dictionary:
    # key - map file name, value - telegram local storage key
    def __ReadMap(self, map_data: dict) -> dict:
        filename = lambda x : x.hex().upper()[::-1]   # Reverse byte order and translate to hex

        out = {}
        while not map_data['stream'].atEnd():
            keyType = struct.unpack('>i', map_data['stream'].readRawData(4))[0]
            if keyType == LSK.lskDraft:
                count = struct.unpack('>i', map_data['stream'].readRawData(4))[0]
                for i in range(count):
                    fileKey = filename(map_data['stream'].readRawData(8))
                    _peerId = struct.unpack('>q', map_data['stream'].readRawData(8))[0]
                    out[fileKey] = keyType
            elif keyType == LSK.lskSelfSerialized:
                data = QByteArray()
                map_data['stream'] >> data
            elif keyType == LSK.lskLocations or keyType == LSK.lskSavedGifs or keyType == LSK.lskUserSettings or keyType == LSK.lskRecentHashtagsAndBots:
                out[filename(map_data['stream'].readRawData(8))] = keyType
            elif keyType == LSK.lskStickersKeys:
                for i in range(4):  # installedStickersKey, featuredStickersKey, recentStickersKey, archivedStickersKey
                    key = filename(map_data['stream'].readRawData(8))
                    out[key] = keyType
            elif keyType == LSK.lskCustomEmojiKeys:
                for i in range(3):  # installedCustomEmojiKey, featuredCustomEmojiKey, archivedCustomEmojiKey
                    key = filename(map_data['stream'].readRawData(8))
                    out[key] = keyType
            else:
                raise ValueError(f"keyType {keyType} doesn't handled")
        logging.info(f"MAP: {out}")
        return out

    def __ParseCache(self, lsk: int, data: QDataStream, version: int) -> list:
        if lsk == LSK.lskLocations:
            locations = []
            EOF = False
            while not data.atEnd():
                location = {}
                location['MK.first'] = struct.unpack('>q', data.readRawData(8))[0]
                location['MK.second'] = struct.unpack('>q', data.readRawData(8))[0]
                location['legacyType'] = struct.unpack('>i', data.readRawData(4))[0]
                location['filename'] = data.readString()
                if version > 9013:
                    bookmark = QByteArray()
                    data >> bookmark
                location['modified'] = QDateTime()
                data >> location['modified']
                location['size'] = struct.unpack('>i', data.readRawData(4))[0]
                if not location['MK.first'] and not location['MK.second'] and not location['legacyType'] and not location['filename'] and not location['size']:
                    EOF = True
                    break
                locations.append(location)
            if EOF:
                count = struct.unpack('>i', data.readRawData(4))[0]
                for i in range(count):
                    raise NotImplementedError("This part was not done")
                if not data.atEnd():
                    web_count = struct.unpack('>i', data.readRawData(4))[0]
                    for i in range(web_count):
                        raise NotImplementedError("Web locations not implemented")
                if not data.atEnd():
                    _downloadsSerialized = QByteArray()
                    data >> _downloadsSerialized
            return locations
        else:
            return []

    def load(self):  # passcode assumed to be '' (otherwise CreateLocalKey should be modified)
        key_path = self._path + os.sep + KEY_FILE + SUFFIX
        key_file_data, _ = self.__readTDF(key_path)
        salt, key_encrypted, info_encrypted = self.__readStreams(key_file_data)

        self.__CreateLocalKey(salt.data())
        self.__DecryptKey(key_encrypted.data())

        info = self.__DecryptLocal(info_encrypted.data(), self._key)
        count = struct.unpack('>i', info['stream'].readRawData(4))[0]
        logging.info(f"Number of accounts: {count}")

        map_path = self._path + os.sep + self._profile + os.sep + MAP_FILE + SUFFIX
        encrypted_map, _ = self.__readTDF(map_path)
        salt, key_encrypted, map_encrypted = self.__readStreams(encrypted_map)
        decrypted_map = self.__DecryptLocal(map_encrypted.data(), self._key)
        map_elements = self.__ReadMap(decrypted_map)

        # Decrypt files from profile
        for cacheSection, keyType in map_elements.items():
            if cacheSection == '0000000000000000':
                continue
            src_filename = self._path + os.sep + self._profile + os.sep + cacheSection + SUFFIX
            dst_filename = self._path + os.sep + OUT_DIR + os.sep + cacheSection + SUFFIX

            file_data, version = self.__readTDF(src_filename)
            encrypted_data,  = self.__readStreams(file_data)   # Comma is needed here as function returns a list (with 1 element)
            decrypted_data = self.__DecryptLocal(encrypted_data.data(), self._key)

            with open(dst_filename, 'wb') as f:
                f.write(decrypted_data['data'].data())

            cache_locations = self.__ParseCache(keyType, decrypted_data['stream'], version)

    # Decrypts given TDEF telegram file that is encrypted with self._key.
    # Output is written in a file with suffix '.dec'
    def decryptTDEF(self, src_file: str):
        file_size = os.stat(src_file).st_size
        with open(src_file, 'rb') as f:
            header = f.read(4)
            assert header == b"TDEF"
            salt = f.read(64)
            format = f.read(1)
            reserved1 = f.read(3)
            reserved2 = f.read(4)
            appVer = f.read(8)
            checkSum = f.read(32)

            m = sha256(self._key[:128])
            m.update(salt[:32])
            key = m.digest()
            m = sha256(self._key[128:])
            m.update(salt[32:])
            iv = m.digest()

            data_size = file_size - 4 - 112 - 16  # 4 - magic, 112 - header, 16 - tail
            assert data_size % BLOCK_SIZE == 0
            data = f.read(data_size)
            tail = f.read(16)

            iiv = bytearray(iv[:16])
            iiv[15] += 3   # +3 is valid only for single data read. It should be modified for decryption of other parts
            iiv = bytes(iiv)

            cipher = AES.new(key, AES.MODE_CTR, initial_value=iiv, nonce=b'')
            decrypted_data = cipher.encrypt(data)

            with open(src_file + DECRYPTED_SUFFIX, 'wb') as f2:
                f2.write(decrypted_data)
