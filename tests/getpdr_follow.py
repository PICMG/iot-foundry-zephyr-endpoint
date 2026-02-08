#!/usr/bin/env python3
"""Request a PDR record and follow GetPDR transfers until the record is complete.

Uses helpers from `run_pldm_tests.py` to build/send MCTP/PLDM frames and parse responses.
"""
import sys
import struct
import time
import os

sys.path.insert(0, os.path.dirname(__file__))
import run_pldm_tests as rt


def le_u32(bs):
    return bs[0] | (bs[1] << 8) | (bs[2] << 16) | (bs[3] << 24)


def get_repository_info(device, baud, verbose=True):
    # Build and send a GetPDRRepositoryInfo request (PLDM cmd 0x50)
    pldm_msg = rt.build_pldm_msg(0x50, rt.PLDM_PLATFORM, 0, b"")
    frame = rt.build_mctp_pldm_request(pldm_msg, dest=0)
    if verbose:
        print('TX GetPDRRepositoryInfo raw:', frame.hex())
    resp = rt.send_and_capture(device, frame, baud)
    if verbose:
        print('RX raw:', resp.hex() if resp else '')
    if not resp:
        print('No response to GetPDRRepositoryInfo')
        return 1, None
    info = rt.parse_frame(resp)
    if not info:
        print('Could not parse GetPDRRepositoryInfo response')
        return 2, None
    resp_bytes = bytes([info['instance'] & 0xFF, info['type'] & 0xFF, info['cmd_code'] & 0xFF]) + info['extra']
    if len(resp_bytes) < 35:
        print('GetPDRRepositoryInfo response too short:', resp_bytes.hex())
        return 3, None
    completion = resp_bytes[3]
    if completion != 0:
        print('GetPDRRepositoryInfo reported completion', completion)
        return 4, None
    # record_count at offset 31..34 (little-endian)
    record_count = resp_bytes[31] | (resp_bytes[32] << 8) | (resp_bytes[33] << 16) | (resp_bytes[34] << 24)
    if verbose:
        print('Repository record_count=', record_count)
    return 0, record_count


def follow_getpdr(device, baud, record_handle=0, request_cnt=0xFE, verbose=True):
    # initial request: data_transfer_handle = 0
    data_transfer_handle = 0
    assembled = bytearray()
    attempt = 0
    next_record_handle = 0
    while True:
        attempt += 1
        # build PLDM GetPDR request payload: record_handle(4), data_transfer_handle(4), transfer_op_flag(1), request_cnt(2), record_chg_num(2)
        # Per DSP0248: GetFirstPart = 0x01, GetNextPart = 0x00
        transfer_op_flag = 0x01 if data_transfer_handle == 0 else 0x00
        record_chg_num = 0
        payload = struct.pack('<I I B H H', record_handle, data_transfer_handle, transfer_op_flag, request_cnt, record_chg_num)
        pldm_msg = rt.build_pldm_msg(0x51, rt.PLDM_PLATFORM, 0, payload)
        frame = rt.build_mctp_pldm_request(pldm_msg, dest=0)
        if verbose:
            print('TX raw:', frame.hex())
        resp = rt.send_and_capture(device, frame, baud)
        if verbose:
            print('RX raw:', resp.hex() if resp else '')
        if not resp:
            print('No response for attempt', attempt)
            return 1, bytes(assembled), None
        info = rt.parse_frame(resp)
        if verbose:
            if info:
                # print selected parsed fields and fcs status
                parsed_summary = {
                    'protocol': info.get('protocol'),
                    'byte_count': info.get('byte_count'),
                    'dest': info.get('dest'),
                    'src': info.get('src'),
                    'flags': info.get('flags'),
                    'msg_type': info.get('msg_type'),
                    'instance': info.get('instance'),
                    'type': info.get('type'),
                    'cmd_code': info.get('cmd_code'),
                    'fcs_ok': info.get('fcs_ok')
                }
                print('RX parsed:', parsed_summary)
            else:
                print('RX parsed: <could not parse>')
        if not info:
            print('Could not parse response frame')
            return 2, bytes(assembled), None

        # reconstruct resp_bytes as in run_pldm_tests
        resp_bytes = bytes([info['instance'] & 0xFF, info['type'] & 0xFF, info['cmd_code'] & 0xFF]) + info['extra']
        if len(resp_bytes) < 15:
            print('Response too short:', resp_bytes.hex())
            return 3, bytes(assembled), None
        completion = resp_bytes[3]
        next_record_handle = le_u32(resp_bytes[4:8])
        returned_transfer_handle = le_u32(resp_bytes[8:12])
        transfer_flag = resp_bytes[12]
        resp_cnt = resp_bytes[13] | (resp_bytes[14] << 8)
        data_start = 15
        data_end = data_start + resp_cnt
        record_chunk = resp_bytes[data_start:data_end]
        if verbose:
            print(f'Attempt {attempt}: completion=0x{completion:02x} transfer_flag=0x{transfer_flag:02x} resp_cnt={resp_cnt} returned_xfer=0x{returned_transfer_handle:08x} next_record_handle=0x{next_record_handle:08x}')
        if completion != 0:
            print('PLDM reported error completion code', completion)
            return 4, bytes(assembled), None

        assembled.extend(record_chunk)

        # If the returned transfer handle is zero the transfer is complete
        if returned_transfer_handle == 0:
            crc = None
            if len(resp_bytes) > data_end:
                crc = resp_bytes[data_end]
            if verbose:
                print('Transfer complete. total_bytes=', len(assembled), 'crc=', crc)
            break

        # otherwise continue using returned_transfer_handle
        if returned_transfer_handle == 0:
            print('Server indicated more data but returned zero transfer handle')
            return 5, bytes(assembled), None
        data_transfer_handle = returned_transfer_handle
        # small delay
        time.sleep(0.05)

    # basic validation: ensure we received some data
    if len(assembled) == 0:
        print('No record data received')
        return 6, bytes(assembled), None
    if verbose:
        print('Successfully retrieved record bytes:', len(assembled))
        print('Sample (first 32 bytes):', assembled[:32].hex())
    return 0, bytes(assembled), next_record_handle


if __name__ == '__main__':
    dev = '/dev/ttyUSB0'
    baud = 115200
    if len(sys.argv) > 1:
        dev = sys.argv[1]
    if len(sys.argv) > 2:
        baud = int(sys.argv[2])
    # allow overriding record_handle (optional - start with specific handle)
    start_rh = None
    if len(sys.argv) > 3:
        start_rh = int(sys.argv[3], 0)

    # First, query repository info
    rc, record_count = get_repository_info(dev, baud, verbose=True)
    if rc != 0:
        print('Failed to get repository info, rc=', rc)
        sys.exit(rc)

    # Iterate records starting at provided handle or 0
    record_handle = start_rh if (start_rh is not None) else 0
    retrieved = 0
    seen_handles = []
    while True:
        print('\n===> Fetching record handle 0x{:08x}'.format(record_handle))
        rc, assembled, next_handle = follow_getpdr(dev, baud, record_handle=record_handle, request_cnt=0xFF, verbose=True)
        if rc != 0:
            print('Failed to fetch record 0x{:08x}, rc={}'.format(record_handle, rc))
            sys.exit(rc)
        retrieved += 1
        seen_handles.append(record_handle)
        print('Retrieved record {} bytes'.format(len(assembled)))
        if not next_handle or next_handle == 0:
            print('No further records (next_handle==0)')
            break
        # continue with next record handle
        record_handle = next_handle

    print('\nRepository reported {} records; retrieved {}'.format(record_count, retrieved))
    if record_count != retrieved:
        print('Mismatch: expected', record_count, 'got', retrieved)
        sys.exit(2)
    print('All records retrieved successfully')
    sys.exit(0)
