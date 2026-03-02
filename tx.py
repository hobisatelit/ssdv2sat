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
import re
import hashlib
import string
import argparse
import configparser
import binascii
from PIL import Image
import shlex
#from reedsolo import RSCodec

DEFAULT_PACKET_LENGTH = 256
DEFAULT_DELAY = 0
DEFAULT_AUDIO_DIR = 'audio'
DEFAULT_FEC = True
DEFAULT_SAMPLE_RATE = 48000
DEFAULT_MAX_WIDTH = 240
DEFAULT_MAX_HEIGHT = 240
# minimum packet for SSDV without FEC / reed solomon. (in bytes)
MIN_SSDV_LENGTH = 26
####################################
VERSION = '0.05'

if DEFAULT_FEC:
    DEFAULT_NOFEC = False
else:
    DEFAULT_NOFEC = True 

ALPHANUM = string.ascii_uppercase + string.digits

FEND = b'\xC0'
FESC = b'\xDB'
TFEND = b'\xDC'
TFESC = b'\xDD'
SPINNER = [
    "▁▂▃▄▅▆▇█▇▆▅▄▃▂▁▁▁▁",
    "▁▁▂▃▄▅▆▇█▇▆▅▄▃▂▁▁▁",
    "▁▁▁▂▃▄▅▆▇█▇▆▅▄▃▂▁▁",
    "▁▁▁▁▂▃▄▅▆▇█▇▆▅▄▃▂▁",
    "▁▁▁▁▁▂▃▄▅▆▇█▇▆▅▄▃▂",
    "▂▁▁▁▁▁▂▃▄▅▆▇█▇▆▅▄▃",
    "▃▂▁▁▁▁▁▂▃▄▅▆▇█▇▆▅▄",
    "▄▃▂▁▁▁▁▂▃▄▅▆▇█▇▆▅▄",
    "▅▄▃▂▁▁▁▂▃▄▅▆▇█▇▆▅▄",
    "▆▅▄▃▂▁▁▂▃▄▅▆▇█▇▆▅▄",
    "▇▆▅▄▃▂▁▁▂▃▄▅▆▇█▇▆▅",
    "█▇▆▅▄▃▂▁▁▁▂▃▄▅▆▇█▇",
    "█▇▆▅▄▃▂▁▁▁▁▂▃▄▅▆▇▇",
    "▇█▇▆▅▄▃▂▁▁▁▁▂▃▄▅▆▇",
    "▆▇█▇▆▅▄▃▂▁▁▁▁▂▃▄▅▆",
    "▅▆▇█▇▆▅▄▃▂▁▁▁▂▃▄▅▄",
    "▄▅▆▇█▇▆▅▄▃▂▁▁▂▃▄▃▂",
    "▃▄▅▆▇█▇▆▅▄▃▂▁▁▂▃▂▂",
    "▂▃▄▅▆▇█▇▆▅▄▃▂▁▁▂▁▁",
    "▁▂▃▄▅▆▇█▇▆▅▄▃▂▁▁▁▁",
    ]

def replace_na(input_string):
    return re.sub(r'\W+', '_', input_string)
    
def show_progress(i, n, width=20):
    p = int(i) / int(n)
    bar = "█" * int(width * p) + "░" * (width - int(width * p))
    print(f"\r{bar} {p:5.1%} - Frags {i:4d}/{n}", end="")

def crc32(filename, sms: bool = False):
    # result = 0 - 255
    if not sms:
        with open(filename, 'rb') as f:
            file_data = f.read()
    else:        
        #file_data = filename.encode('utf-8').hex()
        #file_data = bytes.fromhex(file_data)
        file_data = filename.encode('utf-8')
        
    crc32_value = binascii.crc32(file_data) & 0xff

    return crc32_value

def start_recording(output_filename):
  try:
    command = [DEFAULT_APP_SOX, "-d", "-r", f"{DEFAULT_SAMPLE_RATE}", "-c", "1", "-t", "wav", "-q", "-V1", output_filename]
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
        command = [os.path.join(os.getcwd(),"img2ssdv.py"), "--length", str(packet_length), "--dir", str(output_dir), "--callsign", str(callsign),  input_filename, "--text", str(text), "--quality", str(quality), "--max-size", str(max_w), str(max_h), "--suffix", filesuffix, "--imgid", str(imgid), "--no-fec"]
    
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
    
class tee:
    def __init__(self, *files, log_file=None):
        self.files = files
        self.log_file = log_file
        
    def write(self, obj):
        for f in self.files:
            if f == self.log_file:  
                spinner_patterns = [char for char in SPINNER[0].strip()]
                patterns = ['█', '░'] + spinner_patterns
                
                for pattern in patterns:
                    obj = obj.replace(pattern, '')

            f.write(obj)
            f.flush()
            
    def flush(self):
        for f in self.files:
            f.flush()

def main():
    global DEFAULT_APP_SOX    
    parser = argparse.ArgumentParser(
        description="Convert an image into SSDV, transmit over AX25/IL2P using Dire Wolf KISS and record as audio wav",
        epilog="""Example:
        recommended:
        ./%(prog)s input.jpg
        
        other:
        ./%(prog)s input.jpg --quality 40 --max-size 800 600
        ./%(prog)s input.jpg --norec
        ./%(prog)s input.jpg --max 150 --no-fec
        ./%(prog)s input.jpg --callsign CALSIG
        ./%(prog)s input.jpg --sms "Hello World, message from space"
        ./%(prog)s input.jpg --port 8100
        ./%(prog)s --sms "Hello world!" --norec
        ./%(prog)s input.jpg --callsign CALSIG --turbo --sms "Hello world! this is message from space!" --dest ISS 
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("filename", nargs='?', help="input image file (JPG, PNG, TXT, etc)")
    parser.add_argument("-cs", "--callsign", "--from", help="your actual callsign", default="")
    parser.add_argument("--host", default="127.0.0.1", help="Dire Wolf host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8001, help="Dire Wolf KISS TCP port (default: 8001)")
    parser.add_argument("--turbo", action="store_true", help="EXPERIMENTAL: Remove callsign and basic header. Make header shorter than normal. Make SSDV smaller and faster. If you don't provide a CALLSIGN, turbo mode will be enabled by default")
    parser.add_argument("--ax25", action="store_true", help="Add AX25 frame that contain CALLSIGN, DEST header, total frame and other info. Make header bigger. Default: disable")
    parser.add_argument("--max", type=int, default=DEFAULT_PACKET_LENGTH,
                        help=f"Max data bytes per frame (default: {DEFAULT_PACKET_LENGTH}, non fec min {MIN_SSDV_LENGTH} or fec min {MIN_SSDV_LENGTH + 32}, max 256)")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help=f"Delay between frames in seconds (default: {DEFAULT_DELAY}, use 0.1-3s for longer satellite pass, and 0 for shortest)")
    parser.add_argument("--quality", type=int, default=20,
                        help="JPEG quality 1–95 (default: 20 – good for SSDV)")
    parser.add_argument("--norec", action="store_true", help="No record WAV, tx only to Dire Wolf. Default: tx and record")                      
    parser.add_argument("--fec", action='store_true', default=DEFAULT_FEC, help=f"Encode SSDV packets with FEC (Reed Solomon). Default: {DEFAULT_FEC}") 
    parser.add_argument("--no-fec", action='store_false',default=DEFAULT_NOFEC, dest='fec', help=f"Encode SSDV packets without FEC (Reed Solomon). Default: {DEFAULT_NOFEC}") 
    parser.add_argument("--nolog",  action="store_false", dest="log", default=True, help="disable log. (default: log enable)")
    parser.add_argument("--text", type=str, default='',
                        help="put small text in the top-left corner of the SSDV image") 
    parser.add_argument("--sms", type=str, default='',
                        help="send short message over APRS, prior sending SSDV") 
    parser.add_argument("--dest", "--to", type=str, default='',
                        help="change the destination / sms receiver. default send to your callsigner") 
    parser.add_argument("--max-size", nargs=2, type=int, metavar=("WIDTH", "HEIGHT"),
                        default=[int(DEFAULT_MAX_WIDTH), int(DEFAULT_MAX_HEIGHT)],
                        help=f"Max width and height in pixels (default: {DEFAULT_MAX_WIDTH} {DEFAULT_MAX_HEIGHT})")
    parser.add_argument("--dir", type=str, default=DEFAULT_AUDIO_DIR,
                        help=f"Directory for save recorded audio wav (default: {DEFAULT_AUDIO_DIR})")
    parser.add_argument("--version", action='version', version=f"ssdv2sat-%(prog)s v{VERSION} by hobisatelit <https://github.com/hobisatelit>", help="Show the version of the application")

    args = parser.parse_args()
    
    HOST = args.host
    KISS_PORT = args.port
    SRC_CALL = args.callsign
    PACKET_LENGTH = args.max
    FRAME_DELAY = args.delay
    AUDIO_DIR = args.dir
    filename = args.filename
    FEC_SUFFIX = ''
    ssdv = True

    formatted_time = time.strftime("%Y-%m-%dT%H-%M-%S")
    formatted_time_nosecond = time.strftime("%Y-%m-%d")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    AUDIO_DIR = os.path.join(script_dir, f"{AUDIO_DIR}/{formatted_time_nosecond}")
    os.makedirs(AUDIO_DIR, exist_ok=True)

    if args.log:
        # Open the log file
        log_file = open(f"{AUDIO_DIR}/log.txt", 'a')
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = tee(original_stdout, log_file, log_file=log_file)
        sys.stderr = tee(original_stderr, log_file, log_file=log_file)
        # log command
        print("Log Command: " + shlex.join(sys.argv), file=sys.stderr)
        
    print(f"📺ssdv2sat v{VERSION}")
    
    # check file requirements
    req_error = False
    dep = ['config.ini', 'img2ssdv.py']
    for file in dep:
        if not os.path.exists(file):
            print(f" → Cannot find {file}", file=sys.stderr)
            req_error = True
    if req_error:        
        sys.exit(1)
        
    config = configparser.ConfigParser()
    config.read('config.ini')
    DEFAULT_APP_SOX = config['app']['sox']  
    
    if not args.filename and not args.sms:
        print("error: the following arguments are required: filename")
        print(f"example: ./{parser.prog} input.jpg")
        sys.exit(1)
    
    max_w, max_h = args.max_size
    if max_w < 16 or max_h < 16:
        print("Error: max dimensions must be at least 16 pixels", file=sys.stderr)
        sys.exit(1)
    
    if not args.fec:                
        if not (MIN_SSDV_LENGTH <= args.max <= 256):
            print(f"Error: --max should be between {MIN_SSDV_LENGTH} and 256")
            sys.exit(1)
    else:
        # for ssdv with fec = add 32 bytes for rs
        if not ((MIN_SSDV_LENGTH + 32) <= args.max <= 256):
            print(f"Error: --max should be between {MIN_SSDV_LENGTH + 32} and 256")
            sys.exit(1)
            
    if not (1 <= args.quality <= 95):
        print("Error: quality must be between 1 and 95", file=sys.stderr)
        sys.exit(1)
    if args.delay < 0:
        print("Error: --delay cannot be negative")
        sys.exit(1)
    
    #placeholder
        
    # if user not provide callsign, automatic change to turbo mode
    if not SRC_CALL:
        args.turbo = True
     
    # override args.fec
    if args.turbo:
        #args.fec = False
        #SRC_CALL = ''
        FEC_SUFFIX += '_TURBO'
    if filename:
        filename = os.path.abspath(filename)

        #if not os.path.exists(filename):
        #    print(f"Error: File '{filename}' not found!")
        #    sys.exit(1)
            
        #check file, is it image or not?
        try:
            img = Image.open(filename)
            img.close()
            pass            
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found!", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            #print(f"Error: {str(e)}", file=sys.stderr)
            # Ask user if they want to continue
            response = input(f"You want transmit non image / non SSDV.\nContinue? (yes/no): ").strip().lower()
                
            if response in ['yes', 'y']:
                ssdv = False
                print("Continuing...")
                pass
            else:
                print("Interrupted.")
                sys.exit(0)

        basename = os.path.basename(filename)
        basename_noext = os.path.splitext(basename)[0] + '_'            
        IMG_ID = crc32(filename)
    
    if args.fec:
        FEC_SUFFIX += '_FEC'
    else:
        FEC_SUFFIX += '_NO-FEC'
        
    if ssdv:
        filetype_txt = 'IMG'
        quality_txt = '_' + str(args.quality) + 'q'
        NONSSDV_HEADER_LENGTH = 0
    else:
        if args.fec:
            NONSSDV_HEADER_LENGTH = 45
        else:
            NONSSDV_HEADER_LENGTH = 13
        FEC_SUFFIX += '_NON-SSDV'
        filetype_txt = 'FILE'
        quality_txt = ''
    
    if not filename and args.sms:
        ssdv = False
        # for sms only, without send ssdv
        filetype_txt = 'SMS'
        short_sms = args.sms.strip().lower()
        short_sms = "_".join(short_sms.split()[:5])
        short_sms = replace_na(short_sms)
        short_sms = f"{crc32(args.sms, True)}_" + short_sms 
        IMG_ID = short_sms
        FILE_SUFFIX = f"{filetype_txt}{IMG_ID}"
        basename = FILE_SUFFIX
        basename_noext = ''
    else:
        FILE_SUFFIX = f"{filetype_txt}{IMG_ID}_{PACKET_LENGTH}b_{FRAME_DELAY}s{quality_txt}{FEC_SUFFIX}"
        
    if(args.dest):
        FILE_SUFFIX = f"TO_{args.dest}_" + FILE_SUFFIX     
    if(SRC_CALL):
        FILE_SUFFIX = f"{SRC_CALL}_" + FILE_SUFFIX
    
    output_wav = f"{basename_noext}audio_{FILE_SUFFIX}.wav"

    print(f"{filetype_txt} name         : {basename}")
    print(f"{filetype_txt}_ID           : {IMG_ID}")
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
    data = ''
    if ssdv:
        ssdv_process = img2ssdv(PACKET_LENGTH,AUDIO_DIR,filename,SRC_CALL,args.text,args.quality,args.max_size,FILE_SUFFIX,IMG_ID,args.fec)
        print(ssdv_process)
        if not os.path.exists(os.path.join(AUDIO_DIR, f"{basename_noext}ssdv_{FILE_SUFFIX}.bin")):
            print(f"\nError: SSDV .bin image not found.\nPlease check your config.ini")
            sys.exit(1)
        data = open(os.path.join(AUDIO_DIR, f"{basename_noext}ssdv_{FILE_SUFFIX}.bin"), 'rb').read()
    else:
        if not args.sms:
            print("This function not yet implemented. coming soon")
            sys.exit(0)
            #if filename:
            #    data = open(filename, 'rb').read()
        
    frame_num = 0
    offset = 0
    total_bytes = len(data)
    total_frames = (total_bytes + PACKET_LENGTH - 1) // PACKET_LENGTH

    src_addr = ax25_address(SRC_CALL)
    
    if filename:
        dest_addr = ax25_address(str(hex(IMG_ID)[2:]) + str(hex(total_frames)[2:]), last=True)
    
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

        while send_number:
            if send_number:
                sock.sendall(kiss_sms)
                print(f"{send_number} = Sending {len(sms)} bytes SMS to Dire Wolf...\n") 
                send_number -= 1

    # reduce 6 bytes per ssdv fragments
    total_bytes_real = total_bytes
    if filename and args.turbo:
        total_bytes_real = total_bytes - total_frames * 6
        print("TURBO MODE ENABLE...")

    if total_bytes:      
        print(f"Sending {total_bytes_real} bytes {filetype_txt} to Dire Wolf in ~{total_frames} fragments...\n")

    while offset < total_bytes:
        chunk_size = min(PACKET_LENGTH - NONSSDV_HEADER_LENGTH, total_bytes - offset)
        chunk = data[offset:offset + chunk_size]
        offset += chunk_size
        
        payload = chunk
        
        # old version , prior v0.03 using xf0
        #frame = dest_addr + src_addr + b'\x03\xf0' + payload
        # experimental - x03 = version 0.03:
        
        if args.turbo and ssdv:
            payload = payload[6:]
            
        if args.ax25:
            payload = dest_addr + src_addr + b'\x03\x03' + payload    
            
        frame = payload
            
        kiss_frame = FEND + b'\x00' + kiss_escape(frame) + FEND
        
        try: 
            sock.sendall(kiss_frame)
            if total_frames > 1:
                show_progress(frame_num + 1, total_frames)
                
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
    
    if(wav_process):
        print("\nPress <CTRL+C> only after the sound ends, or the audio won't save completely")
        #SPINNER = ['-', '\\', '|', '/']
        i = 0
        try:
            while True:
                    #sys.stdout.write(f"\r{frame:5d} {seconds} seconds")
                    sys.stdout.write(f" {SPINNER[i % 20]} {(time.perf_counter() - start):.2f} seconds\r")
                    sys.stdout.flush()
                    i += 1
                    time.sleep(0.07)
        except KeyboardInterrupt:
            print("\r  ")
               
        finally:
            print(" → PLEASE WAIT! DONT PRESS ANYKEY!..")   
            time.sleep(3)
            stop_recording(wav_process)
            if os.path.exists(os.path.join(AUDIO_DIR, output_wav)):
                size_mb = os.path.getsize(os.path.join(AUDIO_DIR, output_wav)) / (1024 * 1024)
                print(f"\nWAV file saved as:\n{output_wav} ({size_mb:.2f} MB)")
                print(f"\nReady for playback over radio. 73!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
