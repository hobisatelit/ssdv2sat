Copyright 2026 hobisatelit
https://github.com/hobisatelit/ssdv2sat
License: GPL-3.0-or-later
--- update 2026-04-16 07:19:31 UTC ---

source code aplikasi ini bisa diunduh di: (support linux/windows)
https://github.com/hobisatelit/ssdv2sat

aplikasi ini digunakan untuk mengirim gambar (encoding) dan menerima gambar (decoding) ssdv.
untuk encoding, aplikasi ini mendukung banyak format gambar seperti jpg, png, dll.
cara dan prinsip kerjanya sama seperti mengirim dan menerima sstv.

simpelnya misal A punya foto.jpg. lalu ingin mengirimkan gambar tersebut ke B, melalui HT. 
maka A mengencode foto.jpg menggunakan aplikasi tx.exe dan merekamnya kedalam format audio .wav. lalu memutar dan mentransmisikannya melalui HT. 
di sisi lain B menerima audio melalui HT dan mendecodenya menggunakan aplikasi rx.exe

aplikasi ini juga dapat digunakan untuk saling mengirim dan menerima pesan text sederhana. 
(max: 2029 karakter per pesan). semisal mengirim foto dan artikel text.

aplikasi ini dapat digunakan untuk encode/decode ssdv dari satelit
(contoh: LAPAN-A2/IO86, SilverSat, HADES-SA, dll)

bagaimana cara menggunakannya?

### setup awal

untuk pengaturan pertama kali, kamu harus menginstal VB-Cable. installer download dari sini:
- https://www.VB-CABLE.com
- https://vb-audio.com/Cable/index.htm

untuk os windows yang lebih lama seperti windows 10 dan sebelumnya, direkomendasikan menginstal versi lama (VBCABLE_Driver_Pack43.zip).

setelah instalasi selesai, jangan lupa untuk me-restart komputer agar driver diterapkan.

### pengaturan audio

klik kanan pada ikon speaker di dekat jam, kemudian ikuti langkah-langkah berikut:

1. Pilih **Sounds** (Suara)
2. Pilih tab **Playback** (Pemutaran), klik **CABLE Input**, dan klik tombol **Set Default** (Atur Sebagai Default)
3. Pilih tab **Recording** (Perekaman), klik **CABLE Output**, dan klik tombol **Set Default** (Atur Sebagai Default)
4. Masih di tab **Recording** (Perekaman), klik **Properties** (Properti), pilih tab **Listen** (Dengarkan), centang **Listen to this device** (Dengarkan perangkat ini), pilih **Speakers (xxxx)**, dan klik **OK**
5. Klik **OK**

pengaturan awal sudah selesai. saatnya untuk bermain dengan ssdv.

### menjalankan ssdv2sat

buka folder ssdv2sat. folder ini berisi:

- **rx.exe** — menerima dan mendekode ssdv dan telemetri lainnya (misal aprs)
- **tx.exe** — mengirim dan mengenkode gambar ke dalam audio ssdv
- **direwolf.exe** — modem (fungsi yang sama dengan SoundModem). Secara default, ssdv2sat terhubung ke direwolf di port 8001. 
jika kamu ingin menggunakan SoundModem di Windows, ubah port menjadi 8100.

### memulai modem

pertama, jalankan modem. berikut contoh menggunakan modem direwolf.exe:

1. buka command prompt windows
2. pindah ke direktori tempat kamu mengunduh ssdv2sat
3. Jalankan salah satu perintah berikut:

   - direwolf.exe (secara default, membaca direwolf.conf)
   - direwolf.exe -c lapan-a2.conf (untuk LAPAN-A2)

kamu dapat menyesuaikan modem direwolf dengan mengedit file .conf saat ini, terutama jika kamu memiliki pengaturan perangkat audio yang berbeda.

### cara menerima dan mendekode ssdv

untuk mendekode ssdv, biarkan jendewal direwolf.exe tetap berjalan. lalu jalankan perintah ini di jendela command prompt lain:

rx.exe

Untuk opsi lebih lanjut, bisa dilihat di:

rx.exe --help

secara default, rx.exe mendengarkan modem di port 8001.

jika kamu menggunakan SoundModem (misal: untuk mendekode ssdv dari satelit HADES-SA), kamu harus mengubah port menjadi 8100:

rx.exe --port 8100

## cara mengirim dan meng-enkode gambar

untuk mengirim atau meng-enkode gambar ke dalam ssdv dan merekam audio untuk ditransmisikan di kemudian waktu melalui transceiver / HT kamu, jalankan:

tx.exe

Untuk bantuan, jalankan:

tx.exe --help

### contoh dasar

opsi paling simpel, tercepat, dan terkecil. secara otomatis meng-enkode photo.jpg ke dalam format ssdv dan mengonversinya ke audio wav:
tx.exe photo.jpg 

sama seperti perintah diatas, namun tanpa merekam file audio wav (misal untuk ditransmisikan langsung ke transceiver)
tx.exe photo.jpg --norec

### opsi tambahan

silahkan coba opsi-opsi lainnya:

mengirim gambar ssdv dengan format standard ax25
- tx.exe input.jpg --from MARIO --to LUIGI --ax25

mengirim pesan sms / aprs:
- tx.exe input.jpg --from MARIO --to LUIGI --sms "This is my first SSDV" --ax25

mengirim gambar ssdv dengan kualitas jpg 40 persen, dan resolusi maksimal 800x600 pixel. (cat: makin tinggi makin lama durasi audionya)
- tx.exe input.jpg --quality 40 --max-size 800 600

transmit langsung tanpa merekam audio ke .wav
- tx.exe input.jpg --norec

mengirim ssdv dengan panjang custom 150 bytes per frame (defaultnya 256), dan no-fec = matikan reed solomon 
- tx.exe input.jpg --max 150 --no-fec

mengirim ssdv dengan konek ke modem di port 8100 (port default dari aplikasi soundmodem). misal tidak ingin menggunakan direwolf.
- tx.exe input.jpg --port 8100

- tx.exe input.jpg --callsign CALSIG
- tx.exe input.jpg --sms "Hello World, message from space"
- tx.exe --sms "Hello world!" --norec
- tx.exe input.jpg --callsign CALSIG --turbo --sms "Hello world! this is message from space!" --dest ISS
- tx.exe input.jpg --from CALSIG --turbo --sms "Hello world! this is message from space!" --to ISS

####

contoh skema sederhana menerima dan mengirim gambar via satelit LAPAN-A2 (IO-86):

receive / rx / decode (live):

antenna uhf --> transceiver FM (HT) --> kabel audio --> komputer [ modem direwolf.exe / soundmodem ] --> aplikasi ssdv2sat rx.exe --> cek hasil dekode di folder output

antenna uhf --> RTL-SDR --> SDR Software (contoh SDR++, GQRX, dll) --> [ modem direwolf.exe / soundmodem ] --> aplikasi ssdv2sat rx.exe --> cek hasil dekode di folder output

receive / rx / decode (rekaman):

putar ulang dari rekaman audio. misal kamu bisa lihat contoh2 rekaman dari observasi di satnogs di link ini:
https://community.libre.space/t/io-86-ssdv-experiment/14414. tinggal langsung play saja audio dari browser.

play rekaman audio (browser / media player, dsb) -->  [ modem direwolf.exe ] --> aplikasi ssdv2sat rx.exe --> cek hasil dekode di folder output

---------

transmit / tx / encode (live):

aplikasi ssdv2sat tx.exe (contoh command: "tx.exe photo.jpg --norec") --> [ modem direwolf.exe / soundmodem ] --> kabel audio --> transceiver FM (HT) --> antenna uhf

transmit / tx / encode (rekaman):

rekam dulu audio dengan ssdv2sat tx.exe
contoh command: 
tx.exe photo.jpg

hasil rekamanan cek di folder audio. 

lalu transmit:

player audio (misal rekaman dari komputer di pindah ke handphone) --> kabel audio --> transceiver FM (HT) --> antenna uhf

selamat mencoba!

73!