<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'id' (generated from i18n/id.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Otomatis: {$a} percobaan bot dalam 24 jam';
$string['block'] = 'Blokir';
$string['blockadd'] = 'Blokir alamat atau rentang';
$string['blockadd_desc'] = 'Tidak pernah administrator, juga bukan alamat Anda sendiri. Rentang tidak lebih lebar dari /16 (IPv4) atau /32 (IPv6).';
$string['blockdays'] = 'Selama';
$string['blockdone'] = 'Diblokir: {$a}';
$string['blockedtext'] = 'Permintaan ini dihentikan karena alasan keamanan. Jika menurut Anda ini keliru, hubungi pemilik situs.';
$string['blockedtitle'] = 'Permintaan diblokir';
$string['blockrefused'] = 'Tidak ada yang diblokir: nilainya tidak valid, milik administrator, atau alamat Anda sendiri.';
$string['blocks'] = 'Alamat yang diblokir';
$string['blockvalue'] = 'IP atau rentang (mis. 203.0.113.0/24)';
$string['coldata'] = 'Data';
$string['coldate'] = 'Tanggal (UTC)';
$string['colemail'] = 'Email';
$string['colip'] = 'Alamat';
$string['colmessage'] = 'Pesan';
$string['colreason'] = 'Alasan';
$string['colsigns'] = 'Tanda';
$string['coluntil'] = 'Sampai (UTC)';
$string['colvalue'] = 'Alamat atau email';
$string['colverdict'] = 'Putusan';
$string['colwhere'] = 'Di mana';
$string['days15'] = '15 hari';
$string['days30'] = '30 hari';
$string['days7'] = '7 hari';
$string['days90'] = '90 hari';
$string['done'] = 'Selesai.';
$string['dracoinsomnis:bypassfirewall'] = 'Lewati firewall Draco Insomnis';
$string['events'] = 'Percobaan mencurigakan terakhir';
$string['events_help'] = 'Disimpan 90 hari. Tidak pernah kata sandi. CSV sebuah alamat berisi semua yang dilakukannya, siap dilampirkan ke laporan penyalahgunaan kepada penyedia jaringannya.';
$string['evidence'] = 'Draco Insomnis: blokir dan bukti';
$string['forever'] = 'Selamanya';
$string['geo'] = 'Negara';
$string['geo_desc'] = 'Pengunjung Anda bisa datang dari banyak negara, dan penyerang berganti negara dengan VPN. Saring hanya login, pendaftaran, dan formulir, dan mulailah dengan “Catat saja”. Administrator situs, orang yang Anda izinkan lewat, dan mesin pencari tidak pernah disaring. Firewall harus aktif (catat atau blokir).';
$string['geoaction'] = 'Apa yang dilakukan';
$string['geocountries'] = 'Negara (kode dua huruf, mis. ES, FR, DE)';
$string['geocredit'] = 'Geolokasi IP oleh DB-IP (db-ip.com, CC BY 4.0), diunduh saat Anda mengaktifkan filter dan dicari di server Anda sendiri: tidak ada alamat yang dikirim ke mana pun.';
$string['geomode'] = 'Filter';
$string['geoonly'] = 'Hanya negara dalam daftar';
$string['georefuse'] = 'Tolak negara dalam daftar';
$string['geoscope'] = 'Di mana';
$string['geosensitive'] = 'Login, pendaftaran, dan formulir (disarankan)';
$string['geosite'] = 'Seluruh situs';
$string['headers'] = 'Header keamanan';
$string['headers_desc'] = 'Di halaman: tanpa menebak jenis berkas, tanpa disematkan di situs lain, lebih sedikit data perujuk, tanpa kamera, mikrofon, atau lokasi untuk konten sematan. Tidak pernah header yang sudah dikirim Moodle.';
$string['hsts'] = 'Paksa HTTPS selama 6 bulan (HSTS)';
$string['hsts_desc'] = 'Hanya jika seluruh situs berjalan di HTTPS dan akan tetap begitu: peramban mengingatnya dan menolak HTTP sampai kedaluwarsa.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Menghentikan pendaftaran palsu tanpa captcha: bot tidak mendapat akun, dan setiap percobaan mencurigakan disimpan 90 hari sebagai bukti untuk laporan penyalahgunaan. Tidak ada yang pernah dikirim balik ke penyerang.</p><p>Alamat yang diblokir dan percobaan terakhir: <a href="{$a}">Draco Insomnis: blokir dan bukti</a>.</p>';
$string['modeblock'] = 'Blokir';
$string['modelog'] = 'Catat saja: catat apa yang akan dihentikan';
$string['modeoff'] = 'Mati';
$string['nets'] = 'Jaringan server sewaan';
$string['nets_desc'] = 'Satu rentang per baris (CIDR), ditambahkan ke rentang yang sudah dikenal plugin. Masuk daftar ini hanya menambah poin: dengan sendirinya tidak pernah menjadikan siapa pun bot.';
$string['noblocks'] = 'Saat ini tidak ada yang diblokir.';
$string['noevents'] = 'Belum ada.';
$string['noreviews'] = 'Tidak ada permintaan.';
$string['notdone'] = 'Tidak dapat dilakukan untuk alamat itu.';
$string['pace'] = 'Batas laju anti-salin';
$string['pace_desc'] = 'Yang meminta lebih banyak halaman per menit daripada yang dibaca manusia mendapat “429 Too many requests” sampai menit itu berakhir. Pengguna yang masuk, alamat Anda sendiri, dan mesin pencari yang diverifikasi lewat DNS (Google, Bing, Apple, Yandex) tidak pernah dibatasi. Panggilan AJAX, layanan web, dan berkas tidak dihitung.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Alamat dan email yang diblokir untuk sementara, oleh blokir otomatis atau oleh administrator.';
$string['privacy:metadata:blocks:value'] = 'Alamat IP atau email yang diblokir.';
$string['privacy:metadata:events'] = 'Percobaan mencurigakan (pendaftaran palsu, serangan, penyalinan massal), disimpan 90 hari sebagai bukti untuk laporan penyalahgunaan. Tidak terkait dengan akun Moodle. Tidak pernah kata sandi.';
$string['privacy:metadata:events:fields'] = 'Nama pengguna, email, dan halaman perujuk yang dikirim bersama percobaan.';
$string['privacy:metadata:events:ip'] = 'Alamat IP asal percobaan.';
$string['privacy:metadata:events:timecreated'] = 'Kapan percobaan terjadi.';
$string['privacy:metadata:events:useragent'] = 'Nama peramban atau program yang dikirimnya.';
$string['proxy'] = 'Alamat pengunjung';
$string['proxy_desc'] = 'Biarkan “Alamat koneksi” kecuali situs berada di belakang proxy: header bisa dipalsukan siapa saja.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'Header diabaikan: koneksi ini (<code>{$a}</code>) tidak berasal dari Cloudflare maupun proxy tepercaya. Jika proxy Anda ada di internet, tambahkan alamatnya di “Proxy tepercaya”.';
$string['proxynone'] = 'Alamat koneksi (disarankan)';
$string['proxyxff'] = 'Proxy lain (X-Forwarded-For)';
$string['pwdbreached'] = 'Tolak kata sandi yang ditemukan dalam kebocoran data';
$string['pwdbreached_desc'] = 'Menanyakan Have I Been Pwned dengan k-anonimitas: hanya 5 karakter SHA-1 kata sandi yang keluar dari situs, tidak pernah kata sandinya. Jika layanan tidak menjawab dalam 3 detik, kata sandi diterima. Moodle menerapkannya selama “Kebijakan kata sandi” aktif (Administrasi situs > Keamanan > Pengaturan keamanan situs).';
$string['pwdbreachedrefused'] = 'Kata sandi ini muncul di kebocoran data yang diketahui, jadi penyerang mencobanya lebih dulu. Silakan pilih yang lain.';
$string['pwdmin'] = 'Panjang minimum kata sandi';
$string['pwdmin_desc'] = '8 sampai 64 karakter; 0 hanya menyisakan aturan Moodle sendiri. Berlaku selama “Kebijakan kata sandi” aktif.';
$string['pwdshort'] = 'Kata sandi harus terdiri dari minimal {$a} karakter.';
$string['rateip'] = 'Halaman per menit, per alamat';
$string['ratenet'] = 'Halaman per menit, per jaringan';
$string['ratenet_desc'] = 'Jaringan /24 untuk IPv4 atau /64 untuk IPv6: yang didapat scraper saat berganti-ganti alamat yang berdekatan.';
$string['rejected'] = 'Pendaftaran tidak dapat diselesaikan.';
$string['review1'] = 'Izinkan lewat 24 jam';
$string['review30'] = '30 hari';
$string['review7'] = '7 hari';
$string['reviewapproved'] = 'Izinkan lewat';
$string['reviewattacker'] = 'Penyerang: diblokir';
$string['reviewattackerbtn'] = 'Penyerang';
$string['reviewbody'] = 'Pengunjung yang dihentikan firewall meminta peninjauan. Buka halaman Draco Insomnis untuk mengizinkannya lewat atau tidak.';
$string['reviewbutton'] = 'Minta peninjauan';
$string['reviewdenied'] = 'Ditolak';
$string['reviewdeny'] = 'Tolak';
$string['reviewemail'] = 'Email Anda';
$string['reviewmessage'] = 'Apa yang sedang Anda lakukan?';
$string['reviewreason'] = 'Peninjauan: {$a}';
$string['reviews'] = 'Permintaan peninjauan';
$string['reviewsenttext'] = 'Terima kasih. Pemilik situs akan memeriksanya dan, jika itu kesalahan, mengizinkan Anda lewat.';
$string['reviewsenttitle'] = 'Permintaan terkirim';
$string['reviewshelp'] = 'Orang yang dihentikan firewall dapat memintanya dari halaman blokir. Izinkan lewat untuk sementara jika itu kesalahan. Draco tidak pernah menulis kepada mereka: balas dari email Anda sendiri jika mau.';
$string['reviewsubject'] = '[{$a}] Seseorang meminta Anda meninjau blokir firewall';
$string['shield'] = 'Lindungi pendaftaran mandiri';
$string['shield_desc'] = 'Menambahkan perangkap tak terlihat dan cap halaman bertanda tangan ke formulir pendaftaran (pendaftaran mandiri lewat email). Bot tidak mendapat akun; tiga percobaan bot dalam sehari memblokir alamat selama seminggu.';
$string['summary'] = 'Firewall: 7 hari terakhir';
$string['summaryips'] = 'Alamat paling sibuk:';
$string['summaryline'] = '{$a->total} serangan terlihat, {$a->blocked} diblokir.';
$string['summarywhat'] = 'Apa:';
$string['taskcleanup'] = 'Draco Insomnis: hapus bukti lama dan blokir yang sudah berakhir';
$string['test'] = 'Uji firewall';
$string['testblocked'] = 'Berfungsi: injeksi basis data dikenali dan diblokir (403).';
$string['testhelp'] = 'Mengirim permintaan tak berbahaya berbentuk serangan ke situs dan memberi tahu apa yang terjadi. Tidak dicatat.';
$string['testlogged'] = 'Berfungsi: injeksi basis data dikenali. Dalam «Hanya catat» dicatat tetapi tidak dihentikan; beralih ke «Blokir» saat Anda siap.';
$string['testnone'] = 'Serangan uji tidak dikenali. Mohon laporkan ke Draco Insomnis.';
$string['testoff'] = 'Firewall mati: nyalakan, simpan, lalu uji lagi.';
$string['testunreachable'] = 'Pengujian tidak dapat menjangkau situs dari server itu sendiri (sebagian hosting tidak mengizinkannya). Firewall mungkin tetap bekerja: lihat percobaan terakhir.';
$string['testupstream'] = 'Pengujian dihentikan sebelum mencapai Moodle, oleh firewall milik hosting. Bagus: dua lapis.';
$string['trusted'] = 'Proxy tepercaya';
$string['trusted_desc'] = 'Hanya koneksi dari alamat ini yang boleh menetapkan alamat pengunjung lewat header. Satu alamat atau rentang per baris. Kosong: server ini dan jaringan privat. Rentang milik Cloudflare sudah dikenal.';
$string['unblock'] = 'Buka blokir';
$string['unblocked'] = 'Blokir alamat dibuka.';
$string['waf'] = 'Firewall';
$string['waf_desc'] = 'Menghentikan permintaan berbentuk serangan (injeksi basis data, membaca berkas server, menjalankan kode, skrip dalam tautan) dan pemindai seperti sqlmap atau Nikto. Mulailah dengan “Catat saja” lalu pindah ke “Blokir” setelah beberapa hari. Lima serangan dalam 10 menit memblokir alamat selama seminggu; alamat yang diblokir tetap bisa membaca situs, tetapi tidak bisa mengirim atau masuk. Administrator situs dan pengguna dengan “Lewati firewall Draco Insomnis” tidak pernah diperiksa. Jalan darurat: define(\'DRACO_WAF_OFF\', true); di config.php.';
$string['wafblock'] = 'Firewall: {$a} serangan dalam 10 menit';
$string['yourip'] = 'Alamat Anda menurut plugin: <code>{$a->ip}</code> (alamat koneksi: <code>{$a->remote}</code>). Jika situs berada di belakang Cloudflare atau proxy lain dan keduanya berbeda dari alamat asli Anda, pilih opsi yang sesuai di “Alamat pengunjung”.';
