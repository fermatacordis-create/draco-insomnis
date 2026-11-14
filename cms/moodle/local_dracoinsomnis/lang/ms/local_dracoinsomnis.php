<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'ms' (generated from i18n/ms.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Automatik: {$a} cubaan bot dalam 24 jam';
$string['block'] = 'Sekat';
$string['blockadd'] = 'Sekat alamat atau julat';
$string['blockadd_desc'] = 'Tidak pernah pentadbir, dan bukan alamat anda sendiri. Julat tidak lebih luas daripada /16 (IPv4) atau /32 (IPv6).';
$string['blockdays'] = 'Selama';
$string['blockdone'] = 'Disekat: {$a}';
$string['blockedtext'] = 'Permintaan ini dihentikan atas sebab keselamatan. Jika anda rasa ini satu kesilapan, hubungi pemilik laman.';
$string['blockedtitle'] = 'Permintaan disekat';
$string['blockrefused'] = 'Tiada apa disekat: nilai tidak sah, milik pentadbir, atau alamat anda sendiri.';
$string['blocks'] = 'Alamat yang disekat';
$string['blockvalue'] = 'IP atau julat (cth. 203.0.113.0/24)';
$string['coldata'] = 'Data';
$string['coldate'] = 'Tarikh (UTC)';
$string['colemail'] = 'E-mel';
$string['colip'] = 'Alamat';
$string['colmessage'] = 'Mesej';
$string['colreason'] = 'Sebab';
$string['colsigns'] = 'Tanda';
$string['coluntil'] = 'Hingga (UTC)';
$string['colvalue'] = 'Alamat atau e-mel';
$string['colverdict'] = 'Keputusan';
$string['colwhere'] = 'Di mana';
$string['days15'] = '15 hari';
$string['days30'] = '30 hari';
$string['days7'] = '7 hari';
$string['days90'] = '90 hari';
$string['done'] = 'Selesai.';
$string['dracoinsomnis:bypassfirewall'] = 'Pintas tembok api Draco Insomnis';
$string['events'] = 'Cubaan mencurigakan terkini';
$string['events_help'] = 'Disimpan 90 hari. Tidak pernah kata laluan. CSV sesuatu alamat mengandungi semua yang dilakukannya, sedia untuk dilampirkan pada laporan penyalahgunaan kepada pembekal rangkaiannya.';
$string['evidence'] = 'Draco Insomnis: sekatan dan bukti';
$string['forever'] = 'Selama-lamanya';
$string['geo'] = 'Negara';
$string['geo_desc'] = 'Pelawat anda mungkin datang dari banyak negara, dan penyerang menukar negara dengan VPN. Tapis hanya log masuk, pendaftaran dan borang, dan mulakan dengan “Log sahaja”. Pentadbir laman, orang yang anda benarkan lalu dan enjin carian tidak pernah ditapis. Perlu tembok api dihidupkan (log atau sekat).';
$string['geoaction'] = 'Apa yang perlu dilakukan';
$string['geocountries'] = 'Negara (kod dua huruf, cth. ES, FR, DE)';
$string['geocredit'] = 'Geolokasi IP oleh DB-IP (db-ip.com, CC BY 4.0), dimuat turun apabila anda menghidupkan penapis dan dicari di pelayan anda sendiri: tiada alamat dihantar ke mana-mana.';
$string['geomode'] = 'Penapis';
$string['geoonly'] = 'Hanya negara yang disenaraikan';
$string['georefuse'] = 'Tolak negara yang disenaraikan';
$string['geoscope'] = 'Di mana';
$string['geosensitive'] = 'Log masuk, pendaftaran dan borang (disyorkan)';
$string['geosite'] = 'Seluruh laman';
$string['headers'] = 'Pengepala keselamatan';
$string['headers_desc'] = 'Pada halaman: tiada tekaan jenis fail, tiada pembingkaian oleh laman lain, kurang data rujukan, tiada kamera, mikrofon atau lokasi untuk kandungan terbenam. Tidak pernah pengepala yang sudah dihantar Moodle.';
$string['hsts'] = 'Paksa HTTPS selama 6 bulan (HSTS)';
$string['hsts_desc'] = 'Hanya jika seluruh laman berfungsi dengan HTTPS dan akan terus begitu: pelayar mengingatinya dan menolak HTTP sehingga tamat tempoh.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Menghalang pendaftaran palsu tanpa captcha: bot tidak mendapat akaun, dan setiap cubaan yang mencurigakan disimpan 90 hari sebagai bukti untuk laporan penyalahgunaan. Tiada apa-apa yang dihantar balik kepada penyerang.</p><p>Alamat yang disekat dan cubaan terkini: <a href="{$a}">Draco Insomnis: sekatan dan bukti</a>.</p>';
$string['modeblock'] = 'Sekat';
$string['modelog'] = 'Log sahaja: catat apa yang akan dihalang';
$string['modeoff'] = 'Mati';
$string['nets'] = 'Rangkaian pelayan sewaan';
$string['nets_desc'] = 'Satu julat setiap baris (CIDR), ditambah kepada julat yang sudah diketahui plugin. Berada dalam senarai ini hanya menambah mata: dengan sendirinya ia tidak pernah menjadikan sesiapa bot.';
$string['noblocks'] = 'Tiada apa-apa yang disekat sekarang.';
$string['noevents'] = 'Belum ada apa-apa.';
$string['noreviews'] = 'Tiada permintaan.';
$string['notdone'] = 'Tidak dapat dilakukan untuk alamat itu.';
$string['pace'] = 'Had kadar anti-salin';
$string['pace_desc'] = 'Sesiapa yang meminta lebih banyak halaman seminit daripada yang dibaca manusia mendapat “429 Too many requests” sehingga minit itu tamat. Pengguna yang log masuk, alamat anda sendiri dan enjin carian yang disahkan melalui DNS (Google, Bing, Apple, Yandex) tidak pernah dihadkan. Panggilan AJAX, perkhidmatan web dan fail tidak dikira.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Alamat dan e-mel yang disekat untuk seketika, oleh sekatan automatik atau oleh pentadbir.';
$string['privacy:metadata:blocks:value'] = 'Alamat IP atau e-mel yang disekat.';
$string['privacy:metadata:events'] = 'Cubaan mencurigakan (pendaftaran palsu, serangan, pengikisan), disimpan 90 hari sebagai bukti untuk laporan penyalahgunaan. Tidak dipautkan kepada akaun Moodle. Tidak pernah kata laluan.';
$string['privacy:metadata:events:fields'] = 'Nama pengguna, e-mel dan halaman rujukan yang dihantar bersama cubaan.';
$string['privacy:metadata:events:ip'] = 'Alamat IP asal cubaan itu.';
$string['privacy:metadata:events:timecreated'] = 'Bila cubaan berlaku.';
$string['privacy:metadata:events:useragent'] = 'Nama pelayar atau program yang dihantarnya.';
$string['proxy'] = 'Alamat pelawat';
$string['proxy_desc'] = 'Biarkan “Alamat sambungan” kecuali laman berada di belakang proksi: pengepala boleh dipalsukan oleh sesiapa sahaja.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'Pengepala diabaikan: sambungan ini (<code>{$a}</code>) bukan daripada Cloudflare atau proksi dipercayai. Jika proksi anda berada di internet, tambah alamatnya dalam “Proksi dipercayai”.';
$string['proxynone'] = 'Alamat sambungan (disyorkan)';
$string['proxyxff'] = 'Proksi lain (X-Forwarded-For)';
$string['pwdbreached'] = 'Tolak kata laluan yang ditemui dalam kebocoran data';
$string['pwdbreached_desc'] = 'Bertanya kepada Have I Been Pwned dengan k-anonimiti: hanya 5 aksara SHA-1 kata laluan keluar dari laman, tidak pernah kata laluan itu. Jika perkhidmatan tidak menjawab dalam 3 saat, kata laluan diterima. Moodle menggunakannya selagi “Dasar kata laluan” dihidupkan (Pentadbiran laman > Keselamatan > Tetapan keselamatan laman).';
$string['pwdbreachedrefused'] = 'Kata laluan ini muncul dalam kebocoran data yang diketahui, jadi penyerang mencubanya dahulu. Sila pilih yang lain.';
$string['pwdmin'] = 'Panjang minimum kata laluan';
$string['pwdmin_desc'] = 'Dari 8 hingga 64 aksara; 0 hanya mengekalkan peraturan Moodle sendiri. Digunakan selagi “Dasar kata laluan” dihidupkan.';
$string['pwdshort'] = 'Kata laluan mesti mempunyai sekurang-kurangnya {$a} aksara.';
$string['rateip'] = 'Halaman seminit, bagi setiap alamat';
$string['ratenet'] = 'Halaman seminit, bagi setiap rangkaian';
$string['ratenet_desc'] = 'Rangkaian /24 untuk IPv4 atau /64 untuk IPv6: apa yang diperoleh pengikis apabila bertukar-tukar alamat yang bersebelahan.';
$string['rejected'] = 'Pendaftaran tidak dapat diselesaikan.';
$string['review1'] = 'Benarkan lalu 24 jam';
$string['review30'] = '30 hari';
$string['review7'] = '7 hari';
$string['reviewapproved'] = 'Benarkan lalu';
$string['reviewattacker'] = 'Penyerang: disekat';
$string['reviewattackerbtn'] = 'Penyerang';
$string['reviewbody'] = 'Seorang pelawat yang dihalang oleh tembok api meminta semakan. Buka halaman Draco Insomnis untuk membenarkannya lalu atau tidak.';
$string['reviewbutton'] = 'Minta semakan';
$string['reviewdenied'] = 'Ditolak';
$string['reviewdeny'] = 'Tolak';
$string['reviewemail'] = 'E-mel anda';
$string['reviewmessage'] = 'Apa yang sedang anda lakukan?';
$string['reviewreason'] = 'Semakan: {$a}';
$string['reviews'] = 'Permintaan semakan';
$string['reviewsenttext'] = 'Terima kasih. Pemilik laman akan menyemaknya dan, jika ia satu kesilapan, membenarkan anda lalu.';
$string['reviewsenttitle'] = 'Permintaan dihantar';
$string['reviewshelp'] = 'Orang yang dihentikan tembok api boleh meminta dari halaman sekatan. Benarkan mereka lalu untuk seketika jika ia satu kesilapan. Draco tidak pernah menulis kepada mereka: balas dari mel anda sendiri jika mahu.';
$string['reviewsubject'] = '[{$a}] Seseorang meminta anda menyemak sekatan tembok api';
$string['shield'] = 'Lindungi pendaftaran sendiri';
$string['shield_desc'] = 'Menambah perangkap tidak kelihatan dan cap halaman bertandatangan pada borang pendaftaran (pendaftaran sendiri melalui e-mel). Bot tidak mendapat akaun; tiga cubaan bot dalam sehari menyekat alamat itu selama seminggu.';
$string['summary'] = 'Tembok api: 7 hari terakhir';
$string['summaryips'] = 'Alamat paling aktif:';
$string['summaryline'] = '{$a->total} serangan dilihat, {$a->blocked} disekat.';
$string['summarywhat'] = 'Apa:';
$string['taskcleanup'] = 'Draco Insomnis: buang bukti lama dan sekatan yang tamat';
$string['test'] = 'Uji tembok api';
$string['testblocked'] = 'Berfungsi: suntikan pangkalan data dikenali dan disekat (403).';
$string['testhelp'] = 'Menghantar permintaan tidak berbahaya berbentuk serangan ke laman dan memberitahu apa yang berlaku. Ia tidak dilog.';
$string['testlogged'] = 'Berfungsi: suntikan pangkalan data dikenali. Dalam "Log sahaja" ia dicatat tetapi tidak dihentikan; tukar kepada "Sekat" apabila anda bersedia.';
$string['testnone'] = 'Serangan ujian tidak dikenali. Sila laporkan kepada Draco Insomnis.';
$string['testoff'] = 'Tembok api dimatikan: hidupkan, simpan, kemudian uji lagi.';
$string['testunreachable'] = 'Ujian tidak dapat mencapai laman dari pelayan itu sendiri (sesetengah hos tidak membenarkannya). Tembok api mungkin masih berfungsi: lihat cubaan terkini.';
$string['testupstream'] = 'Ujian dihalang sebelum sampai ke Moodle, oleh tembok api hos itu sendiri. Bagus: dua lapisan.';
$string['trusted'] = 'Proksi dipercayai';
$string['trusted_desc'] = 'Hanya sambungan daripada alamat ini boleh menetapkan alamat pelawat melalui pengepala. Satu alamat atau julat setiap baris. Kosong: pelayan ini dan rangkaian peribadi. Julat milik Cloudflare sudah diketahui.';
$string['unblock'] = 'Nyahsekat';
$string['unblocked'] = 'Sekatan alamat dibuka.';
$string['waf'] = 'Tembok api';
$string['waf_desc'] = 'Menghalang permintaan berbentuk serangan (suntikan pangkalan data, membaca fail pelayan, menjalankan kod, skrip dalam pautan) dan pengimbas seperti sqlmap atau Nikto. Mulakan dengan “Log sahaja” dan tukar kepada “Sekat” selepas beberapa hari. Lima serangan dalam 10 minit menyekat alamat selama seminggu; alamat yang disekat masih boleh membaca laman, tetapi tidak boleh menghantar atau log masuk. Pentadbir laman dan pengguna dengan “Pintas tembok api Draco Insomnis” tidak pernah diperiksa. Jalan keluar kecemasan: define(\'DRACO_WAF_OFF\', true); dalam config.php.';
$string['wafblock'] = 'Tembok api: {$a} serangan dalam 10 minit';
$string['yourip'] = 'Alamat anda seperti yang dilihat oleh plugin: <code>{$a->ip}</code> (alamat sambungan: <code>{$a->remote}</code>). Jika laman berada di belakang Cloudflare atau proksi lain dan alamat ini berbeza daripada alamat sebenar anda, pilih pilihan yang sepadan dalam “Alamat pelawat”.';
