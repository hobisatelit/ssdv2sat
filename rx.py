#!/usr/bin/env python3
# Copyright 2026 hobisatelit
# https://github.com/hobisatelit/ssdv2sat
# License: GPL-3.0-or-later
# SSDV doc: https://ukhas.org.uk/doku.php?id=guides:ssdv
# SSDV-FEC doc: (not yet implemented, coming soon)
# https://destevez.net/2023/05/an-erasure-fec-for-ssdv/
# https://github.com/daniestevez/ssdv-fec/tree/main/ssdv-fec
# some code taken from SSDV Merge - Philip Heron <phil@sanslogic.co.uk>

# This script connects to a Dire Wolf KISS TCP server (port 8001 by default)
# and extracts SSDV packets from payloads (IL2P or non IL2P)
#
# Payload structure from Dire Wolf KISS:
#   bytes 0–15:   AX25 header (used as image fingerprint / unique id)
#   bytes 16–271: SSDV packet (max: 256 bytes total)
#                               
# AX25 packet (16 bytes):
#   bytes 0-6 : dest_field 
#             : decode to ascii, 2 first = file_id, rest = total_frame in hex (max FFFF = 65,535 fragment)
#   bytes 7-13: src_field = sender callsign 
#   bytes 15  : ax25.PID = 0x03 = version 0.03 onward
#
# SSDV packet (max: 256 bytes):
#   offset  0   : sync        0x55
#   offset  1   : sync        0x66=fec / 0x67=no-fec
#   offset 2–5  : callsign   4 bytes
#   offset  6   : image ID    1 byte
#   offset 7–8  : packet ID  2 bytes (big-endian)
#   offset 9,10 : width, height 1 byte
#   offset 11   : flags 1 byte
#   offset 12   : mcu offset 1 byte
#   offset 13-14: mcu index 2 byte
#   NON FEC:
#   offset 15–251  : image data (237 bytes)
#   offset 252-255 : crc32 (4 bytes)
#   FEC:
#   offset 15–219  : image data (205 bytes)
#   offset 220-223 : crc32 (4 bytes)
#   offset 224-255 : fec reed-solomon (32 bytes)
VERSION = '0.05'

import socket
import argparse
import sys
import os
import time
import subprocess
import configparser
import re
from collections import defaultdict
from io import StringIO
import binascii
import struct
import shlex

# minimum packet from modem (in bytes) (direwolf, etc)
MIN_APRS_LENGTH = 1

# minimum packet for SSDV without FEC / reed solomon. (in bytes)
MIN_SSDV_LENGTH = 26

# default value for file2afsk nonstandard ssdv offset (experimental)
OFFSET = 18
DEEPLENGTH = 256

# variable length
VAR_LENGTH = [128,256]

KISS_FEND = b'\xC0'
KISS_DATA_FRAME = 0x00

# ANSI escape codes for colors
YELLOW = "\033[93m"  # Yellow text
BLACK_BACKGROUND = "\033[40m"  # Black background
RESET = "\033[0m"  # Reset to default colors

def highlight(input_string):
    value = f"{YELLOW}{BLACK_BACKGROUND}{input_string}{RESET}" 
    return value

def replace_na(input_string):
    return re.sub(r'\W+', '_', input_string)
    
def show_progress(i, n, width=10):
    p = int(i) / int(n)
    pdec = int(p*100)
    bar = "█" * int(width * p) + "░" * (width - int(width * p))
    output = f"|{bar}| {pdec:5d}% | {i:4d}/{n}"
    return output

def ssdv_decoding(packet_length,input_filename,output_filename):
  try:
    command = [DEFAULT_APP_SSDV, "-v", "-d", "-l", str(packet_length), input_filename, output_filename]
    #return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
  except FileNotFoundError:
    return None
  except subprocess.CalledProcessError as e:
    print(f"An error occurred while running {app_name}: {e}")
    return None

def kiss_unescape(data: bytes) -> bytes:
    #Remove KISS escaping from frame content
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0xDB and i + 1 < len(data):
            if data[i + 1] == 0xDC:
                out.append(0xC0)
            elif data[i + 1] == 0xDD:
                out.append(0xDB)
            else:
                out.append(0xDB)
                out.append(data[i + 1])
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)
   
def parse_ssdv_packet_deep(packet,verbose: bool = False):    
    fec = False  
    dump = ''
    if packet[0] == 0x55:
        if packet[1] == 0x66:
            packet_without_fec = packet[0:(len(packet) - 32)]
            fec =  True           
        elif packet[1] == 0x67:
            packet_without_fec = packet           
        else:
            if verbose:
                print(f" → Invalid sync bytes: {packet[0]:02X} {packet[1]:02X} (expected 55 66 or 55 67)")
            return False

    else:
        if verbose:
            print(f" → Invalid sync bytes: {packet[0]:02X} {packet[1]:02X} (expected 55 66 or 55 67)")
        return False

    # 5566 = b'Uf' = 102 = 0
    # 5567 = b'Ug' = 103 = 1
    # packet = b'Ug' + packet[2:]
    
    # 32 come from min ssdv 64 - fec 32 = 32
    if len(packet_without_fec) < MIN_SSDV_LENGTH:
        if verbose:
            print(f"PACKET TOO SMALL = {len(packet_without_fec)}")
            print(packet.hex())
        return False

    # Unpack packet
    keys = [ 'sync', 'type', 'callsign', 'image_id', 'packet_id',
             'width', 'height', 'flags', 'mcu_offset', 'mcu_index',
             'payload', 'checksum' ]
    parts = struct.unpack('>2BIBH4BH%dsI' % (len(packet_without_fec) - 19), packet_without_fec)
       
    parts = dict(zip(keys, parts))
    
    if fec:
        parts['type'] = '0'
    else:
        parts['type'] = '1'
    
 
    # Test the checksum
    parts['length'] = len(packet)       
    dump += f"LENGTH = {parts['length']}\n"
    crc32 = binascii.crc32(packet[1:len(packet_without_fec) - 4]) & 0xFFFFFFFF
    dump += f"CRC32 = {crc32} = {parts['checksum']}\n"
    if crc32 != parts['checksum']:
        parts['crc32'] = False
        dump += f"CRC = ERROR\n"
    else:
        parts['crc32'] = True
        dump += "CRC = OK\n"
    
    # Decode the callsign
    code = parts['callsign']
    parts['callsign_decode'] = ''
    while code:
        parts['callsign_decode'] += '-0123456789---ABCDEFGHIJKLMNOPQRSTUVWXYZ'[code % 40]
        code //= 40
        
    if not parts['callsign_decode']:
        parts['callsign_decode'] = 'unknown'

    parts['callsign'] = parts['callsign_decode']
     
    dump += f"CODE = {parts['callsign']} = {parts['callsign_decode']}\n"

    # Parse the flags
    parts['quality'] = ((parts['flags'] >> 3) & 7) ^ 4
    parts['eoi'] = (parts['flags'] >> 2) & 1
    parts['mcu_mode'] = parts['flags'] & 0x03
    parts['reserved'] = (parts['flags'] >> 6) & 0x03
    
    dump += f"flags = {parts['flags']}\n"
    dump += f"flags = 0x{parts['flags']:02x} | binary = {bin(parts['flags'])[2:].zfill(8)}\n"
    dump += f"reserved = {parts['reserved']:02b}\n"
    dump += f"quality = {parts['quality']}\n"
    dump += f"eoi = {parts['eoi']}\n"
    dump += f"mcu_mode = {parts['mcu_mode']}\n"
    
    # Count the total number of MCU blocks
    parts['mcu_count'] = parts['width'] * parts['height']
    if parts['mcu_mode'] in (1, 2): parts['mcu_count'] *= 2
    elif parts['mcu_mode'] == 3: parts['mcu_count'] *= 4
    
    if parts['mcu_mode'] == 0:
        parts['width'] *= 16
        parts['height'] *= 16
    elif parts['mcu_mode'] == 1:
        parts['width'] *= 16
        parts['height'] *= 8
        parts['mcu_count'] *= 2
    elif parts['mcu_mode'] == 2:
        parts['width'] *= 8
        parts['height'] *= 16
        parts['mcu_count'] *= 2
    # seen there is bug in ssdv, before it should be 8, then fix with 16. just try    
    elif parts['mcu_mode'] == 3:
        parts['width'] *= 16
        parts['height'] *= 16
        parts['mcu_count'] *= 4
    
    parts['fingerprint'] = '-'.join([
        str(parts['type']),
        str(parts['callsign']),
        str(parts['image_id']),
        str(f"{parts['width']}x{parts['height']}"),
        str(parts['quality']),
        str(parts['mcu_mode']),
    ])
    
    dump += f"fingerprint = {parts['fingerprint']}"
    
    # Include the full packet
    parts['packet'] = packet
    
    if args.verbose:
        print(dump)
        
    if parts['crc32']:
        return parts  
    else:
        return False
    
def ssdv_check(data,var_length,output_dir,verbose: bool = False):
    result = False
    
    # add x00 padd on left side
    packet = data.rjust(300, b'\x00')
    
    # add x00 padd on right side
    packet = packet.ljust(400, b'\x00')
    
    # Write in packet on cache file
    with open(f"{output_dir}/.cache.in", "wb") as f:
        f.write(packet)
    
    extracted_data = defaultdict(dict)
        
    for length in var_length:                                                 
        # save to temporary file, just to check if output is contain packets
        # avoiding delete or remove command
        ssdv_null = ssdv_decoding(length,f"{output_dir}/.cache.in",f"{output_dir}/.cache.out") 
        stdout, stderr = ssdv_null.communicate()  
        if "Read 1 packets" in stderr.decode():
            data = stderr.decode()
            # Initialize a dictionary to store the extracted data
            
            extracted_data['length'] = length
            
            # Extract Skipped bytes
            extracted_data['skipped'] = 0
            skipped_match = re.search(r'Skipped (\d+) bytes.', data)
            if skipped_match:
                extracted_data['skipped'] = int(skipped_match.group(1))
                
            # Extract Callsign
            callsign_match = re.search(r'Callsign: "(.*?)"', data)
            if callsign_match:
                extracted_data['callsign'] = callsign_match.group(1)

            # Extract Image ID
            image_id_match = re.search(r'Image ID: (\d+)', data)
            if image_id_match:
                extracted_data['image_id'] = int(image_id_match.group(1))

            # Extract Resolution (width and height)
            resolution_match = re.search(r'Resolution: (\d+)x(\d+)', data)
            if resolution_match:
                extracted_data['width'] = int(resolution_match.group(1))
                extracted_data['height'] = int(resolution_match.group(2))

            # Extract Packet ID
            packet_id_match = re.search(r'Packet ID: (\d+)', data)
            if packet_id_match:
                extracted_data['packet_id'] = int(packet_id_match.group(1))
            
            extracted_data['error']  = 0    
            # Extract error correction = (\(\d+\) errors corrected)
            error_match = re.search(r'(\d+) errors corrected', data)
            if error_match:
                extracted_data['error'] = int(error_match.group(1))

            # Extract Type
            type_match = re.search(r'Type: (\d+)', data)
            if type_match:
                extracted_data['type'] = int(type_match.group(1))

            # Extract Quality
            quality_match = re.search(r'Quality: (\d+)', data)
            if quality_match:
                extracted_data['quality'] = int(quality_match.group(1))

            # Extract MCU Mode
            mcu_mode_match = re.search(r'MCU Mode: (\d+)', data)
            if mcu_mode_match:
                extracted_data['mcu_mode'] = int(mcu_mode_match.group(1)) 

            extracted_data['crc32'] = True
            
            if not extracted_data['callsign']:
                extracted_data['callsign'] = 'unknown'
                             
            extracted_data['fingerprint'] = '-'.join([
                str(extracted_data['type']),
                str(extracted_data['callsign']),
                str(extracted_data['image_id']),
                str(f"{extracted_data['width']}x{extracted_data['height']}"),
                str(extracted_data['quality']),
                str(extracted_data['mcu_mode']),
            ])
            
            #recovered packet       
            # paket[offset_start:offset_end]     
            extracted_data['packet'] = packet[extracted_data['skipped']:(extracted_data['skipped'] + length)]
                        
            if verbose:
                print(f"SSDV check fingerprint = {extracted_data['fingerprint']}")  
                   
            break
    
    if extracted_data['crc32']:        
        return extracted_data
    else:
        return False

class tee:
    def __init__(self, *files, log_file=None):
        self.files = files
        self.log_file = log_file
        
    def write(self, obj):
        for f in self.files:
            if f == self.log_file:
                obj = obj.replace(YELLOW, "").replace(BLACK_BACKGROUND, "").replace(RESET, "")
                #re.sub only support str data type, result error
                #obj = re.sub(YELLOW|BLACK_BACKGROUND|RESET, '', obj)
            f.write(obj)
            f.flush()
            
    def flush(self):
        for f in self.files:
            f.flush()
    
def main(args):   
    output_dir = args.output_dir         
    print(f"Connecting to Dire Wolf KISS TCP at {args.host}:{args.port} ...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((args.host, args.port))
        print("Connected ✓")
    except Exception as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        sys.exit(1)
        
    print(f"Decode SSDV image fragments to: {output_dir}")
    print(f"Expecting min {MIN_APRS_LENGTH} bytes for APRS and {MIN_SSDV_LENGTH} bytes for SSDV")

    images = defaultdict(dict)
    images_inv = defaultdict(dict)
    parsed = defaultdict(dict)
    images_dump = defaultdict(dict)
    temp_packet = defaultdict(dict)
    parsed_total_frame = defaultdict(dict)
    total_valid = 0
    total_invalid = 0
    total_nonssdv = 0
    total_deepsearch = 0
    total_recovered = 0
    total_all = 0
    total_turbo = 0
    total_sms = 0
    dump = b''
    progress = False
    loop = 0

    packet_buf = bytearray()
    in_frame = False

    temp = ''

    i = 0
    x = 0
    while True:
        try:
            chunk = sock.recv(1024)
        except KeyboardInterrupt:
            print("\nInterrupted by user.")
            break
        except Exception as e:
            print(f"Socket error: {e}", file=sys.stderr)
            break

        if not chunk:
            print("Server closed connection.")
            break        

        for byte in chunk:
            i+=1
            #print(f"work! = {i} {byte}")
            if byte == 0xC0:
                #print("192")
                if in_frame:
                    # Frame complete
                    if len(packet_buf) >= 1:
                        frame_type = packet_buf[0]
                        payload = kiss_unescape(packet_buf[1:])

                        if frame_type == KISS_DATA_FRAME:
                            total_all += 1
                            if len(payload) >= MIN_APRS_LENGTH:
                                if args.verbose:
                                    start_text = f"--- START # {i} ---"
                                    print(highlight(start_text))
                                    print(f"UNMODIFIED PACKET ({len(payload)} bytes): ")
                                    print(payload.hex())

                                #search ssdv header position, support non ax25 frame. search from left to right, byte by byte
                                #ssdv_part = payload[16:]
                                discover = [i for i in range(len(payload)-1) if payload[i:i+2] in (b'\x55\x66', b'\x55\x67')]

                                #packet = b'\x00'
                                
                                bypass = False
                                ssdv_result = ''
                                turbo_text = ''
                                recovered_text = ''
                                packets = [b'\x00',b'\x00']
                                
                                #discover and keep ssdv with normal header first
                                if discover:
                                    position = discover[0]
                                    
                                #then search and try guest ssdv with broken header        
                                elif not discover and len(payload) >= MIN_SSDV_LENGTH - 6: # searching turbo, minus 6 bytes header (2 byte sync type + 4 byte callsign)
                                    # should 67 first, then 66. so all will be checked, look at attempt 1 +ax25
                                    headers = [b'\x67', b'\x66']
                                    position = -1
                                    eoi = False
                                    
                                    # first attempt, guest and fix packet as packet with Turbo header
                                    for header in headers:
                                        # from 0, without 16 byte ax25 frame
                                        if header == b'\x66' and len(payload) < MIN_SSDV_LENGTH + 32:
                                            break
                                             
                                        if args.verbose:
                                            print()
                                            print(f"ATTEMPT 1 ({header.hex()}): TURBO HEADER RECOVERING.. :")
                                                  
                                        packets[0] = b'\x55' + header + b'\x00\x00\x00\x00' + payload
                                        packets[1] = b'\x55' + header + payload
                                        
                                        for ids, packet in enumerate(packets):
                                            ssdv_result = parse_ssdv_packet_deep(packet, args.verbose)
                                            if ssdv_result:
                                                print("signx")
                                                break
                                            if args.verbose:
                                                print(f"Step {ids}")                                                

                                        if ssdv_result:
                                            if ssdv_result['crc32']:
                                                total_turbo += 1
                                                if args.verbose:
                                                    print(f" → RECOVERED 1! {len(payload)} → padded to {len(packet)} bytes")
                                                if packets[0]:
                                                    turbo_text = '(Full Turbo)'
                                                else:
                                                    turbo_text = '(Half Turbo)'
                                                payload = packet
                                                ssdv_bypass_len = len(payload)
                                                position = 0
                                                bypass = True
                                                #if ssdv_result['eoi']:
                                                #    eoi = True
                                                break
                                        else:
                                            if args.verbose:
                                                print(f" → FAIL")
                                        
                                        # from 16, with 16 byte ax25 frame            
                                        if header == b'\x66' and len(payload[16:]) < MIN_SSDV_LENGTH + 32:
                                            break
                                             
                                        if args.verbose:
                                            # this when user tx with option --turbo and --ax25. in turbo mode callsign only put in ax25 frame, not send in ssdv header
                                            print()
                                            print(f"ATTEMPT 1 ({header.hex()}): TURBO HEADER RECOVERING + AX25.. :")

                                        packets[0] = b'\x55' + header + b'\x00\x00\x00\x00' + payload[16:]
                                        packets[1] = b'\x55' + header + payload[16:]
                                        
                                        for ids, packet in enumerate(packets):
                                            ssdv_result = parse_ssdv_packet_deep(packet, args.verbose)
                                            if ssdv_result:
                                                print("signx")
                                                break
                                            if args.verbose:
                                                print(f"Step {ids}")  

                                        if ssdv_result:
                                            if ssdv_result['crc32']:
                                                total_turbo += 1
                                                if args.verbose:
                                                    print(f" → RECOVERED 1! {len(payload)} → padded to {len(packet)} bytes")
                                                if packets[0]:
                                                    turbo_text = '(Full Turbo + AX25)'
                                                else:
                                                    turbo_text = '(Semi Turbo + AX25)'                                                 
                                                payload = payload[0:16] + packet
                                                ssdv_bypass_len = len(packet)
                                                position = 16
                                                bypass = True
                                                #if ssdv_result['eoi']:
                                                #    eoi = True
                                                break
                                        else:
                                            if args.verbose:
                                                print(f" → FAIL")
                                                    
                                    # second attempt, guest and try recover packet as packet with Reed Solomon / FEC            
                                    if not bypass and len(payload) >= MIN_SSDV_LENGTH + 32:
                                        packet = payload
                                        if args.verbose:
                                            print()
                                            print(f"ATTEMPT 2: FEC Reed Solomon RECOVERING (Broken Header).. LENGTH: {len(payload)} bytes...")
                                                    
                                        ssdv_result = ssdv_check(packet, VAR_LENGTH, output_dir, args.verbose)
                                        if ssdv_result:
                                            total_recovered += 1
                                            #accurate len from ssdv_result
                                            ssdv_bypass_len = int(ssdv_result['length'])
                                            if args.verbose:
                                                print(f" → RECOVERED FEC 2 = {len(payload)} → padded to {ssdv_bypass_len} bytes")
                                            recovered_text = f"(Recovered FEC 2 = {ssdv_result['error']} errors corrected)"
                                            payload = ssdv_result['packet']
                                            position = 0
                                            bypass = True
                                        else:
                                            temp_done=''
                                            for length in VAR_LENGTH:
                                                temp_done += f"{length}:"
                                            temp_packet[i,'packet'] = packet
                                            temp_packet[i,'done'] = temp_done
                                            if args.verbose:
                                                print(f" → FAIL, length is not match, will try again latter .. {len(payload)} bytes")
                                                     
                                else:
                                    position = -1
                                        
                                # parsing ax25 frame, applied for sms (non ssdv) and ssdv with ax25 frame
                                file_id = ''
                                img_id = ''
                                pid_field = ''
                                total_frame_text = ''
                                total_frame = 0
                                if position == -1 or position >= 16:
                                    src_field = payload[7:14]
                                    dest_field = payload[0:7]
                                    pid_field = payload[15:16].hex()
                                    
                                    src_call = ''.join(chr(c >> 1) for c in src_field[:6]).strip()
                                    file_id = ''.join(chr(c >> 1) for c in dest_field[:6]).strip()
                                    
                                    src_call = replace_na(src_call)
                                    file_id = replace_na(file_id)       
                                
                                # process both ssdv (normal and broken header)
                                # ssdv or not?
                                if position >= 0:
                                    
                                    invalid = False
                                    save_ssdv = False    
                                    ssdv_part = payload[position:]
                                    ssdv_len = len(ssdv_part)
                                    
                                    # main variable: ssdv_len, ssdv_part and parsed
  
                                    #make sure ssdv length have minimum requirement
                                    if ssdv_len >= MIN_SSDV_LENGTH:
                                        if bypass:
                                        # turbo and fec recovered    
                                            parsed = ssdv_result
                                            #replace ssdv_len with correct length
                                            ssdv_len = ssdv_bypass_len
                                            if args.verbose:
                                                print()
                                                print("PARSE RECOVERY PACKET")
                                            save_ssdv = True
                                        else:
                                        # normal packet
                                            if args.verbose:
                                                print()
                                                print("PARSE NORMAL PACKET")
                                                #print(parsed)
                                            parsed = parse_ssdv_packet_deep(ssdv_part,args.verbose)
                                        if parsed:
                                            #print(parsed)
                                            save_ssdv = True
                                            #if parsed['eoi']:
                                            #    eoi = True    
                                        # only recover fec packet only (with 32 bytes reed solomon)
                                        else:
                                            if ssdv_len >= MIN_SSDV_LENGTH + 32:                                       
                                                packet = ssdv_part
                                                if args.verbose:
                                                    print()
                                                    print(f"ATTEMPT 3: FEC Reed Solomon RECOVERING (Normal header).. LENGTH: {len(ssdv_part)} bytes...")
                                                    print(packet.hex())                
                                                ssdv_result = ssdv_check(packet, VAR_LENGTH, output_dir, args.verbose)
                                                if ssdv_result:
                                                    save_ssdv = True
                                                    broken_ssdv = False
                                                    parsed = ssdv_result
                                                    total_recovered += 1
                                                    ssdv_len = ssdv_result['length']
                                                    ssdv_part = ssdv_result['packet']
                                                    if args.verbose:
                                                        print(f" → RECOVERED FEC 3 = {len(payload)} → padded to {ssdv_len} bytes")
                                                    recovered_text = f"(Recovered FEC 3 = {ssdv_result['error']} errors corrected)"
                                                    
                                                else:
                                                    temp_done=''
                                                    for length in VAR_LENGTH:
                                                        temp_done += f"{length}:"
                                                    temp_packet['packet'][i] = packet
                                                    temp_packet['done'][i] = temp_done
                                                    broken_ssdv = True
                                                    if args.verbose:
                                                        print(f" → FAIL, length is not match, will try again latter {len(payload)} bytes")
                                                        

                                                    #last attempt ..
                                                    #print("LAST ATTEMPT")      
                                                    #print(f"var_length = {VAR_LENGTH}")  
                                                    #print(f"{temp_packet['packet']}")
                                                    #print(f"{temp_packet['done']}")
                                                    
                                                    for length in VAR_LENGTH:
                                                        for n in temp_packet['packet']:
                                                            # print(f"searching {length} === {n} = {temp_packet['done'][n]}")
                                                            if str(length) not in temp_packet['done'][n]:
                                                                packet = temp_packet['packet'][n]
                                                                if args.verbose:
                                                                    print()
                                                                    print(f"ATTEMPT 4: unusual packet length.. try decode with length: {length}")
                                                                    print(packet.hex())          
                                                                single_length = [length]      
                                                                ssdv_result = ssdv_check(packet, single_length, output_dir, args.verbose)
                                                                if ssdv_result:
                                                                    save_ssdv = True
                                                                    parsed = ssdv_result
                                                                    total_recovered += 1
                                                                    ssdv_len = ssdv_result['length']
                                                                    ssdv_part = ssdv_result['packet']
                                                                    if args.verbose:
                                                                        print(f" → RECOVERED FEC 4 = {len(packet)} → padded to {ssdv_len} bytes")
                                                                    recovered_text = f"(Recovered FEC 4 = {ssdv_result['error']} errors corrected)"
                                                                    temp_packet['packet'].pop(n)
                                                                    temp_packet['done'].pop(n)
                                                                else:
                                                                    temp_packet['done'][n] += f"{length}:"

                                                                    
                                                    # last attempt end ..       
                                                    
                                       
                                            
                                        
                                        if save_ssdv: 
                                            #add VALID LENGTH                  
                                            if save_ssdv and ssdv_len not in VAR_LENGTH:
                                                VAR_LENGTH.append(ssdv_len)
                                                if args.verbose:
                                                    print()
                                                    print(f" → Add new length: {ssdv_len}")
                                            
                                            
                                            # support for ax25 enabled frame (total frame)
                                            if position >= 16:
                                                #callsign = src_call
                                                try:
                                                    # support backward for old ssdv2sat
                                                    if pid_field == 'f0':
                                                        img_id = f"_{file_id[0:3]}"
                                                        total_frame = int(file_id[3:],16)
                                                        total_frame_text = f"/ {total_frame}"
                                                    elif pid_field == '03':   
                                                        img_id = f"_{file_id[0:2]}"
                                                        total_frame = int(file_id[2:],16)
                                                        total_frame_text = f"/ {total_frame}"
                                                except ValueError:
                                                    pass 

                                            #print(f"file_id = {file_id} | superb: {total_frame_text}")    
                                            callsign = parsed['callsign']
                                            ssdv_normal = False
                                            ssdv_text = ""
                                            
                                            #print(f"parsed = {parsed}")

                                            if parsed['type'] == "0":
                                                ssdv_normal = True 
                                                ssdv_text = "FEC"
                                            elif parsed['type'] == "1":
                                                ssdv_normal = False 
                                                ssdv_text = "NON FEC"
                                            else:
                                                ssdv_text = "??"
                                                     
                                            #print(f"parsed = {parsed}")

                                            if save_ssdv:
                                                fingerprint = f"{parsed['fingerprint']}_{ssdv_len}bs"                                                                                      
                                                key = (callsign, fingerprint)
                                                
                                                was_new = len(images[key]) == 0
                                                
                                                images[key][parsed['packet_id']] = ssdv_part
                                                
                                                 
                                                '''
                                                fname_noext = f"{parsed['callsign']}{parsed['image_id']}"
                                                fname = f"{fname_noext}.bin"
          
                                                print(f"FILENAME = {fname}-------------------")    
                                                print(f"PARSED = {parsed}-------------------")   

                                                path = os.path.join(f"{output_dir}{add_deep}", fname)
                                                '''
                                            
                                                fname_noext = f"{fingerprint}"
                                                fname = f"{fname_noext}.bin"
                                                path = os.path.join(f"{output_dir}", fname)
                                                
                                                #print(f"WRITE: {parsed['packet_id']}")
                                                #print(ssdv_part.hex())

                                                # Write in packet ID order
                                                with open(f"{path}", "wb") as f:
                                                    for pid in sorted(images[key]):
                                                        f.write(images[key][pid])
                                                    
                                            #print(f"====== temp {temp} - {file_id} =============")

                                            if progress:
                                                if temp != fingerprint: 
                                                    print()                                                    
                                                    
                                            temp = fingerprint     
                                            if was_new:
                                                print(f" ✱ New from: {callsign}, image: {parsed['image_id']} ({ssdv_len} bytes/frag) ({ssdv_text}) {turbo_text}") 
                                                
                                            if not args.simple:
                                                print(f" → {callsign:<7} | IMG {parsed['image_id']:<14} | Pkt {parsed['packet_id']:8d}"
                                                      f" | {(str(len(images[key])) + str(total_frame_text)):>7} frags {recovered_text}")
                                            else:
                                                    
                                                if total_frame:
                                                    #print(f"total frame  = {total_frame}")     
                                                    progress = show_progress(len(images[key]), total_frame)
                                                else:
                                                    progress = f"| {len(images[key]):4d} frags"  
                                                
                                                '''
                                                if save_ssdv:
                                                    print(f"\r → {callsign:<7} | IMG {parsed['image_id']:<14} | Pkt {parsed['packet_id']:8d} {progress} {recovered_text}", end="")    
                                                elif broken_ssdv:
                                                    print(f"\r → {callsign:<7} | IMG {parsed['image_id']:<14} | Pkt {parsed['packet_id']:8d} {progress} - FAIL", end="") 
                                                '''
                                                print(f"\r → {callsign:<7} | IMG {parsed['image_id']:<14} | Pkt {parsed['packet_id']:8d} {progress} {recovered_text}", end="")  
                                                progress=True
                                                
                                            if args.verbose:
                                                if progress:
                                                    print()
                                                print(f" → FROM:{callsign} → DEST:{file_id} | PID: {pid_field} | Identified SSDV: {ssdv_text} @{position} ({ssdv_len} bytes) :")
                                                print("" + ssdv_part.hex())
                                                print(" → Full Payload (AX25 + Data):")
                                                print(payload.hex())
                                                
                                            total_valid += 1
                                            ssdv_process = ssdv_decoding(ssdv_len,os.path.join(f"{output_dir}", fname),os.path.join(f"{output_dir}", f"{fname_noext}.jpg"))
                                        else:
                                            invalid = True
                                            
                                    else:
                                        invalid = True
                                        
                                    if invalid:
                                        total_invalid += 1
                                        #at least show the sender of broken ssdv
                                        #look at ax25 frame first
                                        if position >= 16:
                                            callsign = src_call
                                        else:
                                            callsign = 'unknown'
                                            
                                        if not args.simple:
                                            print(f"\r → {callsign:<7} | IMG {'?':<14} | Pkt {'?':>8} | {'BROKEN':>13}")

                                else:
                                    ### START non ssdv
                                    #if args.verbose:
                                    #    print(f"non ssdv: {len(payload)}")
                                    #    print(payload.hex())
                                    total_nonssdv += 1

                                    # simple anti spam
                                    if args.nofilter:
                                        # show all
                                        ssdv_part = payload
                                        process_nonssdv = True
                                    else:
                                        ssdv_part = ''
                                        # add allowed nonssdv here:
                                        # put whitelist here:
                                        patterns = [
                                            b'\x00' * 16
                                        ]

                                        discover = [i for pattern in patterns 
                                                    for i in range(len(payload) - len(pattern) + 1)
                                                    if payload[i:i+len(pattern)] == pattern]
                                        '''
                                        if discover:
                                            print(payload.hex())
                                            print(f"discover: {len(discover)} = {discover}")
                                        '''
                                        if src_call.count('_') + file_id.count('_') <= 1 and ((len(src_call) >=3 and len(file_id) >=3) or (not src_call and not file_id) or (not src_call and file_id)):
                                            ssdv_part = payload[16:]
                                            process_nonssdv = True
                                        elif discover:
                                            ssdv_part = payload
                                            process_nonssdv = True 
                                        else:
                                            process_nonssdv = False
                                            #total_filter += 1
                                    
                                    ssdv_len = len(ssdv_part)
                                    # only save non ssdv that contain text other than ax25 frame
                                    if process_nonssdv and ssdv_len:
                                        text = ''
                                        # option: ignore / replace / backslashreplace / strict
                                        text = ssdv_part.decode('UTF-8', errors='ignore')

                                        # Keep ASCII [^ -~] AND emojis, remove everything else
                                        cleaned_text = re.sub(r'[^ -~\U0001F300-\U0001F9FF]+', '', text)
                                        cleaned_text = cleaned_text.replace('\n', '').replace('\r', '')

                                        if not args.onlyssdv:
                                            if progress:
                                                print()
                                                progress = False
                                                
                                            if cleaned_text:
                                                highlight_text = highlight(cleaned_text)    
                                                print(f" → {src_call:<7} | {file_id:<18} | OTHER # {total_nonssdv:4d} | {highlight_text}")
                                                temp = file_id
                                                total_sms += 1
                
                                            if args.verbose:
                                                print()
                                                print(f" → PID: {pid_field}")
                                                print(f" → Data only in text")
                                                print(text) 
                                                print(f" → Data only in HEX: ({ssdv_len} bytes)")
                                                print(ssdv_part.hex())
                                                print(" → Full Payload (AX25 + Data):")
                                                print(payload.hex())
                                        
                                        key = src_call
                                        images_inv[key,'hex'][total_nonssdv] = ssdv_part
                                        images_inv[key,'txt'][total_nonssdv] = cleaned_text
                                        
                                        if not src_call:
                                            src_call = 'unknown'
                                        
                                        path_bin = os.path.join(f"{output_dir}/other", f"{src_call}.bin")
                                        path_ascii = os.path.join(f"{output_dir}/other", f"{src_call}.txt")
                                        
                                        if args.newline:
                                            nl = '\n'
                                        else:
                                            nl = ''
                                            
                                        with open(path_bin, "wb") as f:
                                            for pid in sorted(images_inv[key,'hex']):
                                                f.write(images_inv[key,'hex'][pid])
                                                
                                        with open(path_ascii, "w", encoding='utf-8') as f:
                                            for pid in sorted(images_inv[key,'txt']):
                                                f.write(f"{images_inv[key,'txt'][pid]}{nl}")
                                    ### end non ssdv

                                    
                                if args.verbose:  
                                    end_text = f"--- END # {i} ---"
                                    print(highlight(end_text))
                                    print()
                                    print()
                            
                            else:
                                total_nonssdv += 1
                                if args.verbose:
                                    print(f"# {i} - {payload.hex()} ({len(payload)} bytes)")

                    packet_buf = bytearray()
                    in_frame = False
                else:
                    #print("NO")
                    in_frame = True
                    packet_buf = bytearray()
            elif in_frame:
                #x+=1
                #print(f"APPEND {x} = {byte}")
                packet_buf.append(byte)
    #print()
    sock.close()
                
    print(f"\nFinished."
          f"\n → {total_valid} valid SSDV packets. ({total_turbo} Turbo packets included)" 
          f"\n + {total_invalid} broken SSDV packets."
          f"\n + {total_nonssdv} non SSDV packets ({total_nonssdv - total_sms} filter out, {total_sms} SMS)"
          f"\n = {total_all} TOTAL ALL packets."
          f"\n → {total_recovered} FEC (Reed Solomon) Recovered SSDV packets.")
          #f"\n → Deep Search found {total_deepsearch} SSDV images."

    if total_valid > 0:
        print(f"\nFiles created in output/ ({len(images)} images):")
        for (call, img), frags in sorted(images.items()):
            print(f"  {img}  →  {len(frags)} fragments")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Dire Wolf KISS TCP → SSDV → sorted .bin files → JPEG image"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Dire Wolf host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8001, help="Dire Wolf KISS TCP port (default: 8001)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print hex of each received SSDV candidate + parsing details")
    parser.add_argument("-s", "--simple", action="store_true", help="Simple UIX with eye-catching progress bar for certain fragments")
    #parser.add_argument("-d", "--deep", action="store_true", help="experimental for deep searching SSDV")
    #parser.add_argument("--deeplength", type=int, default=DEEPLENGTH, help=f"SSDV packet length for deep searching. Default: {DEEPLENGTH}")
    #parser.add_argument("--offset", type=int, default=OFFSET, help=f"experimental support for non standard SSDV. Default: {OFFSET}")
    parser.add_argument("-o", "--onlyssdv", action="store_true", help="only print on screen SSDV packets")
    parser.add_argument("-nf", "--nofilter", action="store_true", help="disable filter for non SSDV packets")
    parser.add_argument("-nl", "--newline", action="store_true", help="add newline at the end of every non SSDV text data")
    parser.add_argument("-nlog", "--nolog",  action="store_false", dest="log", default=True, help="disable log. (default: log enable)")
    parser.add_argument("--version", action='version', version=f"ssdv2sat-%(prog)s v{VERSION} by hobisatelit <https://github.com/hobisatelit>", help="Show the version of the application")
    args = parser.parse_args()
    
    '''
    if not (64 <= args.deeplength <= 256):
        print("Error: --deeplength should be between 64 and 256")
        sys.exit(1)
    '''
    
    formatted_time = time.strftime("%Y-%m-%dT%H-%M-%S")
    formatted_time_nosecond = time.strftime("%Y-%m-%dT%H-%M")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, f"output/{formatted_time_nosecond}")
    os.makedirs(f"{output_dir}/other", exist_ok=True)
    
    args.output_dir  = output_dir
        
    if args.log:
        # Open the log file
        log_file = open(f"{output_dir}/log.txt", 'a', encoding='utf-8')
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = tee(original_stdout, log_file, log_file=log_file)
        sys.stderr = tee(original_stderr, log_file, log_file=log_file)
        # log command
        print("Log Command: " + shlex.join(sys.argv), file=sys.stderr)

    print(f"📺 ssdv2sat v{VERSION}")
    
    # check file requirements
    req_error = False
    dep = ['config.ini']
    for file in dep:
        if not os.path.exists(file):
            print(f" → Cannot find {file}", file=sys.stderr)
            req_error = True
    if req_error:        
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read('config.ini')
    DEFAULT_APP_SSDV = config['app']['ssdv']
    
    try:
        main(args)
    except KeyboardInterrupt:
        if args.log:
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            log_file.close()
        print("\nInterrupted.")
