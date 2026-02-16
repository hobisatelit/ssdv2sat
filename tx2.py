#!/usr/bin/env python3
# Copyright 2026 hobisatelit
# https://github.com/hobisatelit/ssdv2sat
# License: GPL-3.0-or-later
# SSDV doc: https://ukhas.org.uk/doku.php?id=guides:ssdv
# minimum byte:
# SSDV with FEC = 53 bytes (header 15 byte + data 2 byte + crc 4 byte + reedsolomon 32 byte)
# SSDV without FEC = 21 bytes (header 15 byte + data 2 byte + crc 4 byte)


import socket
import sys
import time
import subprocess
import signal
import threading
import os
import hashlib
import string
import argparse
import configparser
import binascii

DEFAULT_PACKET_LENGTH = 256
DEFAULT_DELAY = 0
DEFAULT_AUDIO_DIR = 'audio'
####################################
VERSION = '0.04'

ALPHANUM = string.ascii_uppercase + string.digits

FEND = b'\xC0'
FESC = b'\xDB'
TFEND = b'\xDC'
TFESC = b'\xDD'

def show_progress(i, n, width=20):
    p = int(i) / int(n)
    bar = "█" * int(width * p) + "░" * (width - int(width * p))
    print(f"\r{bar} {p:5.1%} - Frags {i:4d}/{n}", end="")

def crc32(filename):
    # result = 0 - 255
    with open(filename, 'rb') as f:
        file_data = f.read()
        crc32_value = binascii.crc32(file_data) & 0xff
    return crc32_value

def start_recording(output_filename):
  try:
    command = [DEFAULT_APP_SOX, "-d", "-r", "44100", "-c", "1", "-t", "wav", "-q", "-V1", output_filename]
    return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
  except FileNotFoundError:
    print(f"Error: {DEFAULT_APP_SOX} not found. Make sure its installed.\nCheck config.ini. Audio file not created..")
    return None
  except subprocess.CalledProcessError as e:
    print(f"An error occurred while running {DEFAULT_APP_SOX}: {e}")
    return None
    
    
def img2ssdv(packet_length,output_dir,input_filename,callsign,text,quality,max_size,filesuffix,imgid,fec):
  try:
    max_w, max_h = max_size
    if fec:
        command = [os.path.join(os.getcwd(),"img2ssdv.py"), "--length", str(packet_length), "--dir", str(output_dir), "--callsign", str(callsign),  input_filename, "--text", str(text), "--quality", str(quality), "--max-size", str(max_w), str(max_h), "--suffix", filesuffix, "--imgid", str(imgid), "--fec"]
    else:
        command = [os.path.join(os.getcwd(),"img2ssdv.py"), "--length", str(packet_length), "--dir", str(output_dir), "--callsign", str(callsign),  input_filename, "--text", str(text), "--quality", str(quality), "--max-size", str(max_w), str(max_h), "--suffix", filesuffix, "--imgid", str(imgid)]
    
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # waiting until app finish 
    stdout, stderr = process.communicate()
    return stdout.decode().strip()
  except FileNotFoundError:
    print(f"\nError: img2ssdv.py not found. SSDV image not created..")
    return None
  except subprocess.CalledProcessError as e:
    print(f"An error occurred while running img2ssdv.py: {e}")
    return None

def stop_recording(process):
    process.terminate()
    process.wait(timeout=3)
    process.kill()

def kiss_escape(data):
    data = data.replace(FESC, FESC + TFESC)
    data = data.replace(FEND, FESC + TFEND)
    return data

def ax25_address(call, last=False):
    call_padded = call.ljust(6).upper()[:6] + " "
    addr = bytes([ord(c) << 1 for c in call_padded[:6]])
    ssid = (ord(call_padded[6]) << 1) | 0x60
    if last:
        ssid |= 1
    addr += bytes([ssid])
    return addr

def main():
    parser = argparse.ArgumentParser(
        description="Convert an image into SSDV, transmit over AX25/IL2P using Dire Wolf KISS and record as audio wav",
        epilog="Example:./tx.py [CALSIG] input.jpg"
    )
    parser.add_argument("callsign", nargs='?', help="your actual callsign", default="")
    parser.add_argument("filename", help="input image file (JPG, PNG, etc)")
    parser.add_argument("--host", default="127.0.0.1", help="Dire Wolf host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8001, help="Dire Wolf KISS TCP port (default: 8001)")
    parser.add_argument("--turbo", action="store_true", help="EXPERIMENTAL")
    parser.add_argument("--max", type=int, default=DEFAULT_PACKET_LENGTH,
                        help=f"Max data bytes per frame (default: {DEFAULT_PACKET_LENGTH}, min 21, max 256)")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help=f"Delay between frames in seconds (default: {DEFAULT_DELAY}, use 0.1-3s for longer satellite pass, and 0 for shortest)")
    parser.add_argument("--quality", type=int, default=20,
                        help="JPEG quality 1–95 (default: 20 – good for SSDV)")
    parser.add_argument("--norec", action="store_true", help="No record WAV, tx only to Dire Wolf. Default: tx and record")                      
    parser.add_argument("--fec", action="store_true", help="Encode SSDV packets with FEC. Default: non FEC")
    parser.add_argument("--text", type=str, default='',
                        help="put small text in the top-left corner of the SSDV image") 
    parser.add_argument("--sms", type=str, default='',
                        help="send short message over APRS, prior sending SSDV") 
    parser.add_argument("--dest", type=str, default='',
                        help="change the destination / sms receiver. default send to your callsigner") 
    parser.add_argument("--max-size", nargs=2, type=int, metavar=("WIDTH", "HEIGHT"),
                        default=[320, 320],
                        help="Max width and height in pixels (default: 320 320)")
    parser.add_argument("--dir", type=str, default=DEFAULT_AUDIO_DIR,
                        help=f"Directory for save recorded audio wav (default: {DEFAULT_AUDIO_DIR})")
    parser.add_argument("--version", action='version', version=f"ssdv2sat-%(prog)s v{VERSION} by hobisatelit <https://github.com/hobisatelit>", help="Show the version of the application")

    args = parser.parse_args()
    
    max_w, max_h = args.max_size
    if max_w < 16 or max_h < 16:
        print("Error: max dimensions must be at least 16 pixels", file=sys.stderr)
        sys.exit(1)
                    
    if not (21 <= args.max <= 256):
        print("Error: --max should be between 21 and 256")
        sys.exit(1)
    if not (1 <= args.quality <= 95):
        print("Error: quality must be between 1 and 95", file=sys.stderr)
        sys.exit(1)
    if args.delay < 0:
        print("Error: --delay cannot be negative")
        sys.exit(1)

    HOST = args.host
    KISS_PORT = args.port
    SRC_CALL = args.callsign
    PACKET_LENGTH = args.max
    FRAME_DELAY = args.delay
    AUDIO_DIR = args.dir
    filename = args.filename
    FEC_SUFFIX = ''
    
    # override args.fec
    if args.turbo:
        args.fec = False
        SRC_CALL = ''
        FEC_SUFFIX = '_TURBO'

    os.makedirs(AUDIO_DIR, exist_ok=True)

    filename = os.path.abspath(filename)

    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found!")
        sys.exit(1)

    basename = os.path.basename(filename)
    basename_noext = os.path.splitext(basename)[0]
    
    IMG_ID = crc32(filename)
    
    if args.fec:
        FEC_SUFFIX = "_FEC"
    
    FILE_SUFFIX = f"{SRC_CALL}_IMG{IMG_ID}_{PACKET_LENGTH}b_{FRAME_DELAY}s_{args.quality}q{FEC_SUFFIX}"
    
    output_wav = f"{basename_noext}_audio_{FILE_SUFFIX}.wav"

    print(f"Image name        : {basename}")
    print(f"IMG_ID            : {IMG_ID}")
    print(f"PACKET_LENGTH     : {PACKET_LENGTH} byte/frame")
    print(f"Frame delay       : {FRAME_DELAY} seconds")
    print(f"Audio output      : {output_wav}")
    print(f"AUDIO DIR         : {os.path.join(os.getcwd(),AUDIO_DIR)}/")
    print(f"KISS target       : {HOST}:{KISS_PORT}\n")

    # === KISS CONNECTION CHECK ===
    print("Checking KISS connection to Dire Wolf...", end=" ")
    sys.stdout.flush()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((HOST, KISS_PORT))
        print("SUCCESS ✓")
    except socket.timeout:
        print("\nError: Connection timed out.")
        print("   → Is Dire Wolf running with KISSPORT 8001 enabled?")
        sys.exit(1)
    except ConnectionRefusedError:
        print("\nError: Connection refused.")
        print("   → Dire Wolf not listening on port 8001.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: Unexpected connection error: {e}")
        sys.exit(1)

    # === Proceed ===
    print()
    ssdv_process = img2ssdv(PACKET_LENGTH,AUDIO_DIR,filename,SRC_CALL,args.text,args.quality,args.max_size,FILE_SUFFIX,IMG_ID,args.fec)
    print(ssdv_process)

    if not os.path.exists(os.path.join(AUDIO_DIR, f"{basename_noext}_ssdv_{FILE_SUFFIX}.bin")):
        print(f"\nError: SSDV .bin image not found.\nPlease check your config.ini")
        sys.exit(1)

    data = open(os.path.join(AUDIO_DIR, f"{basename_noext}_ssdv_{FILE_SUFFIX}.bin"), 'rb').read()
    frame_num = 0
    offset = 0
    total_bytes = len(data)
    total_frames = (total_bytes + PACKET_LENGTH - 1) // PACKET_LENGTH

    src_addr = ax25_address(SRC_CALL)
    dest_addr = ax25_address(str(IMG_ID) + str(hex(total_frames)[2:]), last=True)
    
    dest_sms = src_addr
    if args.dest:
        dest_sms = ax25_address(args.dest)
    
    if not args.norec:
        print("\nStarting WAV recording...")
        wav_process = start_recording(os.path.join(AUDIO_DIR, output_wav))
            
        if not wav_process:
            print("Warning: No WAV file created. btw you can record this audio using another app. 73!")
        
    # start counting time
    start = time.perf_counter()
    time.sleep(2)
    print()
    
    send_number = 0

    if args.sms:
        sms = args.sms
        smshex = sms.encode('utf-8').hex()
        payload = bytes.fromhex(smshex)
        frame = dest_sms + src_addr + b'\x03\xf0' + payload
        kiss_sms = FEND + b'\x00' + kiss_escape(frame) + FEND
        send_number = 1
        print(f"Sending {len(sms)} bytes SMS to Dire Wolf...\n")   

    # reduce 6 bytes per ssdv fragments
    total_bytes_real = total_bytes
    if args.turbo:
        total_bytes_real = total_bytes - total_frames * 6
        print("TURBO MODE ENABLE...")
          
    print(f"Sending {total_bytes_real} bytes to Dire Wolf in ~{total_frames} fragments...\n")

    while offset < total_bytes:
        chunk_size = min(PACKET_LENGTH, total_bytes - offset)
        chunk = data[offset:offset + chunk_size]
        offset += chunk_size
        
        payload = chunk
        
        # old version , prior v0.03 using xf0
        #frame = dest_addr + src_addr + b'\x03\xf0' + payload
        # experimental - x03 = version 0.03:
        
        if args.turbo:
            payload = payload[6:]
            frame = payload
        else:
            frame = dest_addr + src_addr + b'\x03\x03' + payload
            
        kiss_frame = FEND + b'\x00' + kiss_escape(frame) + FEND
        
        try:
            if send_number:
                sock.sendall(kiss_sms)
                send_number -= 1
                
            sock.sendall(kiss_frame)
            if total_frames > 1:
                show_progress(frame_num, total_frames-1)
        except BrokenPipeError:
            print("\nError: Connection lost during transmission.")
            sock.close()
            stop_recording(wav_process)
            sys.exit(1)
            
        frame_num += 1
        
        time.sleep(FRAME_DELAY)
    sock.close()
    
    if args.norec:
        print("\nDone!")
        sys.exit(0)
    
    print()    
    spinner = [
    "▁▂▃▄▅▆▇█▇▆▅▄▃▂▁   ",
    " ▁▂▃▄▅▆▇█▇▆▅▄▃▂▁▁ ",
    "  ▁▂▃▄▅▆▇█▇▆▅▄▃▂▁ ",
    "   ▁▂▃▄▅▆▇█▇▆▅▄▃▂▁",
    "▁   ▁▂▃▄▅▆▇█▇▆▅▄▃▂",
    "▂▁   ▁▂▃▄▅▆▇█▇▆▅▄▃",
    "▃▂▁   ▁▂▃▄▅▆▇█▇▆▅▄",
    "▄▃▂▁  ▁▂▃▄▅▆▇█▇▆▅ ",
    "▅▄▃▂▁ ▁▂▃▄▅▆▇█▇▆▅ ",
    "▆▅▄▃▂▁▁▂▃▄▅▆▇█▇▆▅ ",
    "▇▆▅▄▃▂▁▁▂▃▄▅▆▇█▇▆ ",
    "█▇▆▅▄▃▂▁ ▁▂▃▄▅▆▇█ ",
    "█▇▆▅▄▃▂▁▁ ▁▂▃▄▅▆▇ ",
    "▇█▇▆▅▄▃▂▁  ▁▂▃▄▅▆▇",
    "▆▇█▇▆▅▄▃▂▁  ▁▂▃▄▅▆",
    "▅▆▇█▇▆▅▄▃▂▁ ▁▂▃▄▅▄",
    "▄▅▆▇█▇▆▅▄▃▂▁▁▂▃▄▃ ",
    "▃▄▅▆▇█▇▆▅▄▃▂▁▁▂▃▂ ",
    "▂▃▄▅▆▇█▇▆▅▄▃▂▁▁▂▁ ",
    "▁▂▃▄▅▆▇█▇▆▅▄▃▂▁▁  ",
    ]
    
    if(wav_process):
        print("\nPress <CTRL+C> only after the sound ends, or the audio won't save completely")
        #spinner = ['-', '\\', '|', '/']
        i = 0
        try:
            while True:
                    #sys.stdout.write(f"\r{frame:5d} {seconds} seconds")
                    sys.stdout.write(f" {spinner[i % 20]} {(time.perf_counter() - start):.2f} seconds\r")
                    sys.stdout.flush()
                    i += 1
                    time.sleep(0.07)
        except KeyboardInterrupt:
            print("\r  ")
               
        finally:   
            time.sleep(3)
            stop_recording(wav_process)
            if os.path.exists(os.path.join(AUDIO_DIR, output_wav)):
                size_mb = os.path.getsize(os.path.join(AUDIO_DIR, output_wav)) / (1024 * 1024)
                print(f"\nWAV file saved to:\n{output_wav} ({size_mb:.2f} MB)")
                print(f"\nReady for playback over radio. 73!")

if __name__ == "__main__":
    print(f"📺ssdv2sat v{VERSION}")
    
    config = configparser.ConfigParser()
    config.read('config.ini')
    DEFAULT_APP_SOX = config['app']['sox']
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
