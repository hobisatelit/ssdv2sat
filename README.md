# ssdv2sat
send and receive image (support jpg, png, etc) from satellite using handheld radio FM. (take advantage of IL2P + Reed Solomon + SSDV)

With this script you can create IL2P modulated WAV (baudrate 1200-9600) automaticaly from a picture/image file to be transmitted via a handheld FM radio, and vice versa. Example: send and receive SSDV JPEG image over analog IL2P 1200 modulation from terestrial or VR satellites

### Dependencies:
Debian/Ubuntu Linux
```bash
sudo apt update
sudo apt install python3 sox git pavucontrol
```
#### install latest Direwolf (IL2P support). 
look at [this link for details](https://github.com/wb2osz/direwolf)


#### install latest SSDV. 
look at [this link for details](https://github.com/fsphil/ssdv)
```bash
cd ~
git clone https://github.com/fsphil/ssdv
cd ssdv
make
sudo make install
```

### Download the script:
```bash
cd ~
git clone https://github.com/hobisatelit/ssdv2sat.git && cd ssdv2sat
chmod 755 *.py
```
### Config Pavucontrol
You only need to set this up once. The goal is for the sox application (audio recorder) and direwolf (KISS server) to be able to listen to the audio output from the speakers or line out of the computer.

Open three terminal 

on first terminal run Direwolf KISS server
```bash
cd ~/ssdv2sat
direwolf -c direwolf.conf
```

on second terminal run
```bash
sox -d -r 44100 -c 1 /tmp/test.wav
```

on third terminal run
```bash
pavucontrol
```
look at **Recording** tab, you will see **direwolf** app and **sox** there, please change capture to **MONITOR** mode both of them. and then you can close both app with press Ctrl+C on each terminal.

### How to convert image or picture into WAV  
Run Direwolf KISS server
```bash
cd ~/ssdv2sat
direwolf -c direwolf.conf
```
on another terminal run below command. 
note: replace ABCDEF with your CALLSIGN. replace image.jpg with your image file. Script support many picture format: JPEG, PNG, etc. check at audio folder to see the result.
```bash
cd ~/ssdv2sat
./tx.py ABCDEF image.jpg
```

### How to convert WAV into picture
```bash
cd ~/ssdv2sat
./rx.py
```
play your recorded wav file or directly stream from SDR app, and the **rx.py** script will auto detect the image inside the signal. when finish, press Ctrl+C. the binary and image will be saved as .bin and .jpg in **output** directory

### How to change  Dire Wolf baudrate
edit direwolf.conf at same directory with script. 
change MODEM 1200 to MODEM 2400, or MODEM 9600. higher baudrate, faster transmission. Please adjust according to your hardware support. Handheld FM ussualy support 1200 and 2400 only. 

### How to run on Windows
personally i never test it on Windows. but it should also work. Dire Wolf, ssdv and sox are available for Windows os. Please check config.ini to change the location of these apps.

### Another advanced command
```bash
cd ~/ssdv2sat
./tx.py -h
./rx.py -h
./rx.py -s

recommended:
./tx.py input.jpg

# set my **callsign MARIO**, then create modulated wav from **image file mario-poster.jpg**,
# connect to dire wolf kiss server at **ip 192.168.10.1, port 8080**,
# set **maximum length** per ssdv packet 195 bytes,
# set **delay** 1 second between packet transmission,
# save all output into **directory** recording
# send short message (sms) to ISS, with message Hello World
./tx.py MARIO mario-poster.jpg --host 192.168.10.1 --port 8080 --max 195 --delay 1 --dir recording --sms "Hello world! this is message from space!" --dest ISS
```

