import struct


class TFTPClient:
    def __init__(self, target, port, socks_client):
        self.target = target
        self.port = port
        self.socks_client = socks_client

    def get_file(self, filename, timeout=10, retries=5):
        """Download a file via TFTP. Works through SOCKS5 or direct UDP.

        Returns file data as bytes, or None on failure.
        Implements retry logic, OACK handling, error opcode handling,
        and duplicate block detection.
        """
        rrq = b'\x00\x01' + filename.encode('ascii') + b'\x00' + b'octet' + b'\x00'

        # Send initial Read Request
        self.socks_client.send(rrq, (self.target, self.port))

        filedata = bytearray()
        expected_block = 1
        last_ack = None
        transfer_addr = (self.target, self.port)

        for attempt in range(retries):
            try:
                data, transfer_addr = self.socks_client.recvfrom(9076, timeout=timeout)
                break
            except Exception:
                if attempt < retries - 1:
                    print(f"[!] TFTP: No response to RRQ, retrying ({attempt + 1}/{retries})...")
                    self.socks_client.send(rrq, (self.target, self.port))
                else:
                    print("[!] TFTP request timed out waiting for first response")
                    return None

        while True:
            opcode = struct.unpack(">H", data[:2])[0]

            # OACK (opcode 6) — option acknowledgment
            if opcode == 6:
                # ACK block 0 to accept options
                ack = struct.pack(">HH", 4, 0)
                self.socks_client.send(ack, transfer_addr)
                last_ack = ack
                try:
                    data, transfer_addr = self.socks_client.recvfrom(9076, timeout=timeout)
                except Exception:
                    print("[!] TFTP: Timed out after OACK acknowledgment")
                    return None
                continue

            # ERROR (opcode 5)
            if opcode == 5:
                error_code = struct.unpack(">H", data[2:4])[0]
                error_msg = data[4:].rstrip(b'\x00').decode('ascii', errors='replace')
                print(f"[!] TFTP error {error_code}: {error_msg}")
                return None

            # DATA (opcode 3)
            if opcode != 3:
                print(f"[!] TFTP: Unexpected opcode {opcode}")
                return None

            block = struct.unpack(">H", data[2:4])[0]
            block_data = data[4:]

            if block == expected_block:
                filedata += block_data
                expected_block += 1
            elif block == expected_block - 1:
                # Duplicate block — re-ACK without appending data
                pass
            else:
                print(f"[!] TFTP: Unexpected block {block}, expected {expected_block}")
                return bytes(filedata) if filedata else None

            # Send ACK for the received block
            ack = struct.pack(">HH", 4, block)
            self.socks_client.send(ack, transfer_addr)
            last_ack = ack

            # Last block — transfer complete (data < 512 bytes)
            if len(block_data) < 512:
                return bytes(filedata)

            # Wait for next block with retry logic
            got_response = False
            for retry in range(retries):
                try:
                    data, transfer_addr = self.socks_client.recvfrom(9076, timeout=timeout)
                    got_response = True
                    break
                except Exception:
                    if retry < retries - 1:
                        # Re-send last ACK
                        self.socks_client.send(last_ack, transfer_addr)
                    else:
                        print(f"[!] TFTP: Timed out waiting for block {expected_block} after {retries} retries")
                        return bytes(filedata) if filedata else None
