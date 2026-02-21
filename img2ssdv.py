#!/usr/bin/env python3
# Copyright 2026 hobisatelit
# https://github.com/hobisatelit/ssdv2sat
# License: GPL-3.0-or-later
VERSION = '0.04'
"""
Convert the image to a SSDV-compatible JPEG. By default, FEC (Reed-Solomon) is disabled.
This is because we have configured direwolf.conf with IL2P, which enhances AX.25 using FEC

Features:
- Resize proportionally to fit within max_width × max_height
- Force dimensions to multiple of 16 (SSDV requirement)
- Quality default 20 (user can override)
- 4:2:0 chroma subsampling
- Floating point DCT (Pillow/libjpeg default in most builds)
- No progressive scan
- No EXIF, XMP, IPTC, thumbnails, ICC profile
- Optimize file size (huffman tables)

Usage:
    python img2ssdv.py input.jpg
    python img2ssdv.py input.jpg --max-size 640 480 --callsign ABCDEF --text "Hello World" --quality 30 --suffix hobi --nofec
"""
import os
import argparse
import sys
import subprocess
from PIL import Image, ImageDraw, ImageFont
import configparser

DEFAULT_PACKET_LENGTH = 256

DEFAULT_FEC = False

# minimum packet for SSDV without FEC / reed solomon. (in bytes)
MIN_SSDV_LENGTH = 26

if DEFAULT_FEC:
    DEFAULT_NOFEC = False
else:
    DEFAULT_NOFEC = True 

def make_multiple_of_16(n: int) -> int:
    """Round down to nearest multiple of 16 (SSDV needs 16×16 MCU blocks)."""
    return (n // 16) * 16

def resize_to_fit_keep_aspect(
    img: Image.Image,
    max_w: int,
    max_h: int
) -> Image.Image:
    """Resize proportionally so image fits inside max_w × max_h."""
    orig_w, orig_h = img.size
    ratio = min(max_w / orig_w, max_h / orig_h)

    if ratio >= 1.0:
        new_w, new_h = orig_w, orig_h
    else:
        new_w = int(orig_w * ratio)
        new_h = int(orig_h * ratio)

    # Force multiples of 16
    new_w = make_multiple_of_16(new_w)
    new_h = make_multiple_of_16(new_h)

    # Minimum 16×16 to avoid invalid SSDV
    new_w = max(new_w, 16)
    new_h = max(new_h, 16)

    return img.resize((new_w, new_h), Image.Resampling.LANCZOS)
    
def text_topleft(im, text):
    """Small white text on semi-black box. Upper left. No drama."""
    draw = ImageDraw.Draw(im, "RGBA")

    try:
        font = ImageFont.truetype("arial.ttf", 10)
    except OSError:
        font = ImageFont.load_default()

    # Measure text (modern Pillow way, fallback for old crap)
    try:
        bbox = draw.textbbox((0, 0), text, font=font)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
    except AttributeError:
        tw, th = draw.textsize(text, font=font)

    pad = 4
    x, y = 4, 4
    boxw = tw + pad*2
    boxh = th + pad*2

    # Black semi-transparent box
    draw.rectangle((x, y, x+boxw, y+boxh), fill=(0, 0, 0, 50))

    # White text
    draw.text((x + pad, y + pad), text, font=font, fill=(255, 255, 255, 255))

    return im

def ssdv_encoding(packet_length,input_filename,output_filename,callsign,quality,imgid,fec):
  try:
    #auto adjust ssdv quality     
    q = min(7, max(0, round((quality - 10) / 12)))
    if fec:  
        command = [DEFAULT_APP_SSDV, "-e", "-q", str(q), "-l", str(packet_length), "-c", str(callsign), "-i", str(imgid), input_filename, output_filename]
    else:
        command = [DEFAULT_APP_SSDV, "-e", "-n", "-q", str(q), "-l", str(packet_length), "-c", str(callsign), "-i", str(imgid), input_filename, output_filename] 
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stderr.decode().strip()
  except FileNotFoundError:
    return f"\nError: {DEFAULT_APP_SSDV} not found\n{output_filename} not created\nCheck config.ini"
  except subprocess.CalledProcessError as e:
    print(f"An error occurred while running {app_name}: {e}")
    return None
    

def main():
    parser = argparse.ArgumentParser(
         description="Convert image to SSDV-compatible JPEG",
         epilog="Example: ./img2ssdv.py input.jpg"
    )
          
    parser.add_argument("input", help="Input image filename (JPG, PNG, etc.)")
    parser.add_argument("--max-size", nargs=2, type=int, metavar=("WIDTH", "HEIGHT"),
                        default=[320, 320],
                        help="Max width and height in pixels (default: 320 320)")
    parser.add_argument("--callsign", type=str, default='ABCDEF',
                        help="your actual callsign (default: ABCDEF)")
    parser.add_argument("--text", type=str, default=None,
                        help="put small text top-left corner of the image")   
    parser.add_argument("--quality", type=int, default=20,
                        help="JPEG quality 1–95 (default: 20 – good for SSDV)")      
    parser.add_argument("--imgid", type=int, default=0,
                        help="Image ID 0–255 (default: 0)")            
    parser.add_argument("--length", type=int, default=DEFAULT_PACKET_LENGTH,
                        help=f"SSDV packet length (default: {DEFAULT_PACKET_LENGTH}), between {MIN_SSDV_LENGTH}-256 without fec or {MIN_SSDV_LENGTH + 32}-256 with fec")
    parser.add_argument("--dir", type=str, default=".",
                        help="output directory (default: .)") 
    parser.add_argument("--suffix", type=str, default="",
                        help="filename suffix") 
    parser.add_argument("--fec", action='store_true', default=DEFAULT_FEC, help=f"Encode SSDV packets with FEC (Reed Solomon). Default: {DEFAULT_FEC}") 
    parser.add_argument("--no-fec", action='store_false',default=DEFAULT_NOFEC, dest='fec', help=f"Encode SSDV packets without FEC (Reed Solomon). Default: {DEFAULT_NOFEC}") 
    parser.add_argument("--version", action='version', version=f"ssdv2sat-%(prog)s v{VERSION} by hobisatelit <https://github.com/hobisatelit>", help="Show the version of the application")
    
    args = parser.parse_args()

    args.input = os.path.abspath(args.input)
    basename = os.path.basename(args.input)
    basename_noext = os.path.splitext(basename)[0]

    if args.suffix:
       args.suffix = f"_{args.suffix}"
       
    args.fec = bool(args.fec)   
        
    small_output_filename = f"{basename_noext}_small{args.suffix}.jpg"
    ssdv_output_filename = f"{basename_noext}_ssdv{args.suffix}.bin"

    max_w, max_h = args.max_size
    if max_w < 16 or max_h < 16:
        print("Error: max dimensions must be at least 16 pixels", file=sys.stderr)
        sys.exit(1)

    if not (1 <= args.quality <= 95):
        print("Error: quality must be between 1 and 95", file=sys.stderr)
        sys.exit(1)
        
    if not (0 <= args.imgid <= 255):
        print("Error: IMG ID must be between 0 and 255", file=sys.stderr)
        sys.exit(1)

    if not args.fec:                
        if not (MIN_SSDV_LENGTH <= args.length <= 256):
            print(f"Error: SSDV packet length must be between {MIN_SSDV_LENGTH} and 256", file=sys.stderr)
            sys.exit(1)
    else:
        if not ((MIN_SSDV_LENGTH + 32) <= args.length <= 256):
            print(f"Error: SSDV packet length must be between {MIN_SSDV_LENGTH + 32} and 256", file=sys.stderr)
            sys.exit(1)
        


    os.makedirs(args.dir, exist_ok=True)

    try:
        with Image.open(args.input) as im:
            # Convert to RGB if necessary (SSDV expects color JPEG)
            if im.mode not in ("RGB", "L"):
                im = im.convert("RGB")
            elif im.mode == "L":
                im = im.convert("RGB")  # SSDV usually wants color, even if source is grayscale

            # Resize
            im_resized = resize_to_fit_keep_aspect(im, max_w, max_h)
            
            if args.text:
                 im_resized = text_topleft(im_resized, args.text)

            # Save with SSDV-friendly settings
            im_resized.save(
                os.path.join(args.dir, small_output_filename),
                format="JPEG",
                quality=args.quality,
                subsampling=0,           # 0 → 4:2:0 chroma subsampling (standard for SSDV)
                optimize=True,           # Optimize Huffman tables
                progressive=False,       # Baseline JPEG only (no progressive)
                exif=b"",                # Strip all EXIF
                icc_profile=None,        # No color profile
                # Pillow does not write XMP/IPTC/thumbnail unless explicitly added
            )
                                  
            #ssdv auto encode
            ssdv_process = ssdv_encoding(args.length,os.path.join(args.dir, small_output_filename),os.path.join(args.dir,ssdv_output_filename),args.callsign,args.quality,args.imgid,args.fec)

            print(f"\nJPEG Optimization → {small_output_filename}")
            print(f"Resized to   : {im_resized.size[0]}×{im_resized.size[1]} (multiple of 16, aspect preserved)")
            print(f"Quality      : {args.quality}")
            print(f"Subsampling  : 4:2:0")
            print(f"Progressive  : disabled")
            print(f"Metadata     : fully stripped")
            print(f"\nSSDV Encoding → {ssdv_output_filename}")
            print(f"PacketLength : {args.length} bytes")
            print(ssdv_process)
            print(f"FEC (ReedSolomon): {args.fec}")

    except FileNotFoundError:
        print(f"Error: Input file not found → {args.input}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('config.ini')
    DEFAULT_APP_SSDV = config['app']['ssdv']
    main()
