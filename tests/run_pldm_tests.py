#!/usr/bin/env python3
"""Send basic PLDM requests over MCTP and print decoded responses.

Sends: GET_TID, GET_PLDM_VERSION, GET_PLDM_TYPES, GET_PLDM_COMMANDS
to the remote EID (default 0) and prints parsed PLDM response fields.
"""
import time
import serial
import sys
import json
import argparse
import os
import struct

FRAME_CHAR = 0x7E
ESCAPE_CHAR = 0x7D
INITFCS = 0xFFFF


fcstab = [
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48,
    0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7, 0x1081, 0x0108,
    0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e, 0x9cc9, 0x8d40, 0xbfdb,
    0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876, 0x2102, 0x308b, 0x0210, 0x1399,
    0x6726, 0x76af, 0x4434, 0x55bd, 0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e,
    0xfae7, 0xc87c, 0xd9f5, 0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e,
    0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd,
    0xc974, 0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3, 0x5285,
    0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a, 0xdecd, 0xcf44,
    0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72, 0x6306, 0x728f, 0x4014,
    0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c, 0xddd5,
    0xa96a, 0xb8e3, 0x8a78, 0x9bf1, 0x7387, 0x620e, 0x5095, 0x411c, 0x35a3,
    0x242a, 0x16b1, 0x0738, 0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862,
    0x9af9, 0x8b70, 0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e,
    0xf0b7, 0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036, 0x18c1,
    0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e, 0xa50a, 0xb483,
    0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5, 0x2942, 0x38cb, 0x0a50,
    0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd, 0xb58b, 0xa402, 0x9699, 0x8710,
    0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7,
    0x6e6e, 0x5cf5, 0x4d7c, 0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1,
    0xa33a, 0xb2b3, 0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72,
    0x3efb, 0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a, 0xe70e,
    0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1, 0x6b46, 0x7acf,
    0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9, 0xf78f, 0xe606, 0xd49d,
    0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e, 0x58d5, 0x495c,
    0x3de3, 0x2c6a, 0x1ef1, 0x0f78,
]


def calc_fcs(data: bytes) -> int:
    fcs = INITFCS
    for b in data:
        fcs = 0x0ffff & ((fcs >> 8) ^ fcstab[(fcs ^ (b & 0xff)) & 0xff])
    return fcs


def unescape_body(raw: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == ESCAPE_CHAR:
            i += 1
            if i >= len(raw):
                break
            out.append((raw[i] + 0x20) & 0xFF)
        else:
            out.append(b)
        i += 1
    return bytes(out)


def parse_frame(data: bytes):
    if not data:
        return None
    # Find the last complete framed packet (avoid concatenating multiple frames)
    end = data.rfind(FRAME_CHAR)
    if end == -1:
        return None
    start = data.rfind(FRAME_CHAR, 0, end)
    if start == -1:
        return None
    # skip past the start character
    payload = data[start + 1:end]
    
    # unescape the payload
    payload = unescape_body(payload)
    # payload layout: [protocol(1), byte_count(1), body(byte_count), fcs_hi(1), fcs_lo(1)]
    if len(payload) < 2:
        return None
    protocol = payload[0]         # serial protocol version
    byte_count = payload[1]       # number of bytes in the body

    # validate full frame length (body + 2-byte FCS)
    if len(payload) < (2 + byte_count + 2):
        return None

    # extract MCTP body and parse fields from the body to avoid indexing past bounds
    body = payload[2:2 + byte_count]
    if len(body) < 6:
        return None

    header_version = body[0]   # mctp media independent header version
    dest = body[1]             # destination EID
    src = body[2]              # source EID
    flags = body[3]            # flags (som/eom/tag_owner/msg_tag)
    msg_type = body[4]         # message type (0x01 = PLDM)
    # PLDM message header starts at body[5]
    if len(body) < 8:
        # not enough data for PLDM header
        return None
    instance = body[5]
    pldm_type = body[6]
    command_code = body[7]
    # response code may not be present for all messages
    response_code = body[8] if len(body) > 8 else None
    
    # calculate and verify FCS
    fcs_calc = calc_fcs(payload[:2 + byte_count])
    msg_fcs = (payload[2 + byte_count] << 8) | payload[2 + byte_count + 1]
    
    response_index = 3 + 6  # protocol(1)+byte_count(1) + body offset to PLDM payload start
    extra = b""
    # extra is the PLDM payload bytes following the 3-byte PLDM header in the body
    # body starts at payload[2], PLDM header begins at body[5] -> overall index = 2 + 5 = 7
    body_end = 2 + byte_count
    if body_end > (2 + 8):
        # extra bytes after PLDM header (instance/type/command)
        extra = payload[2 + 8:body_end]
    return {
        'protocol': protocol,
        'byte_count': byte_count,
        'header_version': header_version,
        'dest': dest,
        'src': src,
        'flags': flags,
        'msg_type': msg_type,
        'instance': instance,
        'type': pldm_type,
        'cmd_code': command_code,
        'resp_code': response_code,
        'extra': extra,
        'fcs_ok': (fcs_calc == msg_fcs),
        'raw_fcs': msg_fcs,
        'fcs_calc': fcs_calc,
    }


def build_mctp_pldm_request(pldm_msg: bytes, dest: int = 0, src: int = 0x10, msg_type: int = 0x01) -> bytes:
    """Wrap a raw PLDM message (starting with PLDM header) into an MCTP frame.
    Default remote EID is 0 as requested.
    """
    protocol_version = 0x01
    header_version = 0x01
    flags = 0xC8
    body = bytearray()
    body.append(header_version)
    body.append(dest)
    body.append(src)
    body.append(flags)
    ###################################
    # start of em.data / mctp_msg_hdr
    body.append(msg_type)       # IC / message type (0x01 = PLDM)                
    ###################################
    # start of struct pldm_msg_hdr
    body.extend(pldm_msg)       # starts with instance rq/d/instance, PLDM type and command code bytes 
    byte_count = len(body)
    frame = bytearray()
    frame.append(FRAME_CHAR)
    frame.append(protocol_version)
    frame.append(byte_count)
    frame.extend(body)
    fcs = calc_fcs(bytes(frame[1:]))
    frame.append((fcs >> 8) & 0xFF)
    frame.append(fcs & 0xFF)
    frame.append(FRAME_CHAR)
    tx = bytearray()
    payload_start = 3
    payload_end = 3 + byte_count
    for i, b in enumerate(frame):
        if (i >= payload_start) and (i <= payload_end) and (b in (FRAME_CHAR, ESCAPE_CHAR)):
            tx.append(ESCAPE_CHAR)
            tx.append((b - 0x20) & 0xFF)
        else:
            tx.append(b)
    return bytes(tx)


def send_and_capture(device: str, frame: bytes, baud: int = 9600, settle: float = 0.25):
    with serial.Serial(device, baud, timeout=0.01) as ser:
        ser.reset_input_buffer()
        time.sleep(settle)
        ser.write(frame)
        ser.flush()
        data = bytearray()
        last = time.time()
        deadline = time.time() + 5.0
        while time.time() < deadline:
            n = ser.in_waiting
            if n:
                data.extend(ser.read(n))
                last = time.time()
            else:
                if data and (time.time() - last) > 0.2:
                    break
                time.sleep(0.001)

        # Split received stream into individual framed packets
        frames = []
        i = 0
        while True:
            try:
                start = data.index(FRAME_CHAR, i)
                end = data.index(FRAME_CHAR, start + 1)
                # append the inner payload bytes (between flags)
                frames.append(bytes(data[start + 1:end]))
                # allow RFC1662 "shared flag" semantics: do not advance past the
                # end-flag so that the same 0x7E byte can serve as the start of
                # the next frame. Keep `i` at `end` to allow the end byte to be
                # considered the start of the next frame on the following loop.
                i = end
            except ValueError:
                break

        if not frames:
            return bytes()

        # Reassemble MCTP bodies from successive frames until we see EOM set
        assembled_body = bytearray()
        protocol_version = None
        eom_seen = False
        for raw_payload in frames:
            # unescape and parse this frame's payload
            payload = unescape_body(raw_payload)
            if len(payload) < 6:
                continue
            if protocol_version is None:
                protocol_version = payload[0]
            byte_count = payload[1]
            # validate lengths
            if len(payload) < (2 + byte_count + 2):
                continue
            # MCTP body is payload[2:2+byte_count]
            mctp_body = payload[2:2 + byte_count]
            if len(mctp_body) < 5:
                continue
            # flags and message type are inside the MCTP body
            flags = mctp_body[3]
            msg_type = mctp_body[4]
            # Skip non-PLDM (control) messages; they can appear interleaved
            # on the serial channel and should not be appended to the
            # assembled PLDM body. Continue until we see EOM on a PLDM
            # fragment.
            if msg_type != 0x01:
                # still check for EOM on this frame? no — EOM pertains to
                # this specific message type; keep reading until PLDM EOM.
                continue
            assembled_body.extend(mctp_body)
            # In the MCTP header flags, EOM is indicated when bit 6 (0x40) is set
            if (flags & 0x40) != 0:
                eom_seen = True
                break

        if not assembled_body:
            return bytes()

        # Build a synthetic single framed packet containing the assembled body
        proto = protocol_version if protocol_version is not None else 0x01
        byte_count = len(assembled_body)
        frame_buf = bytearray()
        frame_buf.append(FRAME_CHAR)
        frame_buf.append(proto)
        frame_buf.append(byte_count)
        frame_buf.extend(assembled_body)
        fcs = calc_fcs(bytes(frame_buf[1:]))
        frame_buf.append((fcs >> 8) & 0xFF)
        frame_buf.append(fcs & 0xFF)
        frame_buf.append(FRAME_CHAR)

        # escape payload bytes between payload start/end
        tx = bytearray()
        payload_start = 3
        payload_end = 3 + byte_count
        for i, b in enumerate(frame_buf):
            if (i >= payload_start) and (i <= payload_end) and (b in (FRAME_CHAR, ESCAPE_CHAR)):
                tx.append(ESCAPE_CHAR)
                tx.append((b - 0x20) & 0xFF)
            else:
                tx.append(b)
        return bytes(tx)


PLDM_BASE = 0x00
PLDM_PLATFORM = 0x02

# PLDM Commands (base.h)
PLDM_SET_TID = 0x01
PLDM_GET_TID = 0x02
PLDM_GET_PLDM_VERSION = 0x03
PLDM_GET_PLDM_TYPES = 0x04
PLDM_GET_PLDM_COMMANDS = 0x05


def build_pldm_msg(command: int, pldm_type: int = PLDM_BASE, instance: int = 0, payload: bytes = b"") -> bytes:
    # first header byte: request=1, datagram=0, reserved=0, instance_id (5 bits)
    first = (1 << 7) | (0 << 6) | (0 << 5) | (instance & 0x1F)
    # second header byte: type (6 bits) + header_ver (2 bits). header_ver use 0.
    header_ver = 0
    second = ((header_ver & 0x03) << 6) | (pldm_type & 0x3F)
    third = command & 0xFF
    return bytes([first, second, third]) + payload


def pretty_print_pldm_response(resp: bytes):
    print('Raw:', ' '.join(f"{b:02X}" for b in resp))
    info = parse_frame(resp)
    if not info:
        print('  Could not parse frame')
        return
    print('  Src->Dst: {} -> {}'.format(info['src'], info['dest']))
    if info['msg_type'] != 0x01:
        print('  Not a PLDM message (msg_type={})'.format(info['msg_type']))
        return
    # reconstruct PLDM message bytes from parsed pieces
    if info['cmd_code'] is None:
        print('  No PLDM data')
        return
    pldm_bytes = bytes([info['cmd_code']]) + info['extra']
    if len(pldm_bytes) < 3:
        print('  PLDM message too short')
        return
    request = (info['instance'] >> 7) & 0x1
    datagram = (info['instance'] >> 6) & 0x1
    instance = info['instance'] & 0x1F
    pldm_type = info['type'] & 0x3F
    header_ver = (info['type'] >> 6) & 0x03
    payload = pldm_bytes[2:-2]
    print(f'  PLDM: request={request} datagram={datagram} instance={instance} header_ver={header_ver}')
    print(f'  Type::Command: 0x{info["type"]:02X}::0x{info["cmd_code"]:02X}')
    print(f'  Response code: 0x{info["resp_code"]:02X}')
    print(f'  Payload ({len(payload)} bytes):', ' '.join(f"{b:02X}" for b in payload))

def hex_to_bytes(hexstr: str) -> bytes:
    s = ''.join(hexstr.split())
    return bytes.fromhex(s)


def hex_to_pattern(hexstr: str):
    """Convert a hex string possibly containing '**' wildcard byte tokens
    into a list of integers or None (for wildcards). '**' represents one
    ignored byte. Whitespace is ignored.
    """
    s = ''.join(hexstr.split())
    if len(s) % 2 != 0:
        raise ValueError('hex string must have even length')
    pattern = []
    i = 0
    while i < len(s):
        pair = s[i:i+2]
        if pair == '**':
            pattern.append(None)
        else:
            try:
                pattern.append(int(pair, 16))
            except Exception:
                raise
        i += 2
    return pattern


def follow_getpdr(device, baud, record_handle=0, request_cnt=18, verbose=False):
    """Follow a multipart GetPDR transfer until complete. Returns (rc, assembled_bytes).
    rc==0 indicates success.
    """
    assembled = bytearray()
    data_transfer_handle = 0
    attempt = 0
    MAX_ATTEMPTS = 256
    while attempt < MAX_ATTEMPTS:
        attempt += 1
        # build PLDM GetPDR request payload: record_handle(4), data_transfer_handle(4), transfer_op_flag(1), request_cnt(2), record_chg_num(2)
        # Per DSP0248: GetFirstPart = 0x01, GetNextPart = 0x00
        transfer_op_flag = 0x01 if data_transfer_handle == 0 else 0x00
        record_chg_num = 0
        try:
            payload = struct.pack('<I I B H H', int(record_handle), int(data_transfer_handle), int(transfer_op_flag), int(request_cnt), int(record_chg_num))
        except Exception:
            return 10, b""
        pldm_msg = build_pldm_msg(0x51, PLDM_PLATFORM, 0, payload)
        frame = build_mctp_pldm_request(pldm_msg, dest=0)
        resp = send_and_capture(device, frame, baud)
        if not resp:
            if verbose:
                print('No response for attempt', attempt)
            return 1, bytes(assembled)
        info = parse_frame(resp)
        if not info:
            if verbose:
                print('Could not parse response frame')
            return 2, bytes(assembled)

        # Reconstruct resp_bytes as in run_pldm_tests
        resp_bytes = bytes([info['instance'] & 0xFF, info['type'] & 0xFF, info['cmd_code'] & 0xFF]) + info['extra']

        if len(resp_bytes) < 15:
            if verbose:
                print('Response too short:', resp_bytes.hex())
            return 3, bytes(assembled)

        completion = resp_bytes[3]
        next_record_handle = resp_bytes[4] | (resp_bytes[5] << 8) | (resp_bytes[6] << 16) | (resp_bytes[7] << 24)
        returned_transfer_handle = resp_bytes[8] | (resp_bytes[9] << 8) | (resp_bytes[10] << 16) | (resp_bytes[11] << 24)
        transfer_flag = resp_bytes[12]
        resp_cnt = resp_bytes[13] | (resp_bytes[14] << 8)
        data_start = 15
        data_end = data_start + resp_cnt
        record_chunk = resp_bytes[data_start:data_end]
        if verbose:
            print(f'Attempt {attempt}: completion=0x{completion:02x} transfer_flag=0x{transfer_flag:02x} resp_cnt={resp_cnt} returned_xfer=0x{returned_transfer_handle:08x}')
        if completion != 0:
            if verbose:
                print('PLDM reported error completion code', completion)
            return 4, bytes(assembled)

        assembled.extend(record_chunk)

        # If returned_transfer_handle == 0, transfer complete
        if returned_transfer_handle == 0:
            crc = None
            if len(resp_bytes) > data_end:
                crc = resp_bytes[data_end]
            if verbose:
                print('Transfer complete. total_bytes=', len(assembled), 'crc=', crc)
            return 0, bytes(assembled)

        # continue using returned handle
        data_transfer_handle = returned_transfer_handle
        time.sleep(0.02)

    return 5, bytes(assembled)


def run(device='/dev/ttyACM0', baud=9600, tests_path=None, verbose=False):
    # Default tests file is `pldm_run_tests.json` located next to this script
    if not tests_path:
        tests_path = os.path.join(os.path.dirname(__file__), 'pldm_run_tests.json')

    try:
        with open(tests_path, 'r') as f:
            test_list = json.load(f)
    except Exception as e:
        print('Failed to load tests:', e)
        return

    total = 0
    failed = 0
    for t in test_list:
        name = t.get('name', '(unnamed)')
        action = t.get('action')
        payload_hex = t.get('payload')
        expected_hex = t.get('expected')
        expected_code = t.get('expected_code')
        total += 1

        # Support stateful actions driven by JSON
        if action == 'follow_getpdr':
            print('\n===> Sending (follow_getpdr) ', name)
            record_handle = t.get('record_handle', 0)
            request_cnt = t.get('request_cnt', 18)
            rc, assembled = follow_getpdr(device, baud, record_handle=record_handle, request_cnt=request_cnt, verbose=verbose)
            ok = (rc == 0)
            resp_bytes = assembled if (ok and assembled is not None) else b""
            # provide minimal info dict for downstream reporting
            info = {'resp_code': 0 if ok else None}
        else:
            if not payload_hex:
                print('Skipping test (no payload):', name)
                continue

            pldm_msg = hex_to_bytes(payload_hex)
            # Normalize common JSON error: transfer_op_flag sometimes ends up one
            # byte too far (at index 12) in some test vectors. If we detect a
            # PLDM GetPDR (cmd 0x51) where byte 11 is zero and byte 12 looks
            # like a transfer_op_flag (0x00..0x02), shift it into position so
            # firmware sees the flag at the expected offset.
            if len(pldm_msg) >= 13 and pldm_msg[2] == 0x51:
                try:
                    if pldm_msg[11] == 0x00 and pldm_msg[12] in (0x00, 0x01, 0x02):
                        fixed = bytearray(pldm_msg)
                        fixed[11] = fixed[12]
                        # remove the duplicate byte at 12 by shifting the remainder
                        del fixed[12]
                        pldm_msg = bytes(fixed)
                        print('\n===> Normalized GetPDR payload (fixed transfer_op_flag position)')
                except Exception:
                    pass
            # Diagnostic: for GetPDR requests, print payload length and transfer_op_flag byte
            if len(pldm_msg) >= 12 and pldm_msg[2] == 0x51:
                tof = pldm_msg[11]
                print('\n===> Sending', name, f'(len={len(pldm_msg)} transfer_op_flag=0x{tof:02x})')
            else:
                print('\n===> Sending', name)
            frame = build_mctp_pldm_request(pldm_msg, dest=0)
            resp = send_and_capture(device, frame, baud)
            if not resp:
                print('  No response')
                failed += 1
                continue

            info = parse_frame(resp)
            if not info:
                print('  Could not parse response frame')
                failed += 1
                continue

            # Reconstruct PLDM-style response bytes: instance,type,cmd + extra
            try:
                resp_bytes = bytes([
                    info.get('instance', 0) & 0xFF,
                    info.get('type', 0) & 0xFF,
                    (info.get('cmd_code', 0) or 0) & 0xFF,
                ]) + (info.get('extra') or b"")
            except Exception as e:
                print('  Error reconstructing PLDM response:', e)
                print('  Parsed info:', info)
                failed += 1
                continue

        ok = True
        if action == 'follow_getpdr':
            if expected_code is not None:
                # follow_getpdr returns 0 on success; expected_code here indicates desired success(0)
                if expected_code != 0:
                    ok = False
            if expected_hex is not None and resp_bytes is not None:
                try:
                    pattern = hex_to_pattern(expected_hex)
                except Exception:
                    pattern = None
                if pattern is None:
                    ok = False
                else:
                    if len(pattern) > len(resp_bytes):
                        ok = False
                    else:
                        for idx, p in enumerate(pattern):
                            if p is None:
                                continue
                            if p != resp_bytes[idx]:
                                ok = False
                                break
        else:
            if expected_code is not None:
                if info.get('resp_code') != expected_code:
                    ok = False
            if expected_hex is not None:
                try:
                    pattern = hex_to_pattern(expected_hex)
                except Exception:
                    pattern = None
                if pattern is None:
                    ok = False
                else:
                    if len(pattern) != len(resp_bytes):
                        ok = False
                    else:
                        for idx, p in enumerate(pattern):
                            if p is None:
                                continue
                            if p != resp_bytes[idx]:
                                ok = False
                                break

        print('  PASS' if ok else '  FAIL')
        if verbose or not ok:
            print('  input:', payload_hex)
            print('  expected_code:', expected_code)
            print('  expected:', expected_hex)
            print('  got code:', info.get('resp_code'))
            print('  got resp:', ''.join(f"{b:02x}" for b in resp_bytes))
        if not ok:
            failed += 1

    print('\nSummary: {}/{} failed'.format(failed, total))


if __name__ == '__main__':
    dev = '/dev/ttyUSB0'
    baud = 115200
    if len(sys.argv) > 1:
        dev = sys.argv[1]
    if len(sys.argv) > 2:
        baud = int(sys.argv[2])
    tests_path = None
    if len(sys.argv) > 3:
        tests_path = sys.argv[3]
    run(dev, baud, tests_path)
