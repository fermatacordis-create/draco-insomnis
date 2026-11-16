<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'uz' (generated from i18n/uz.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Avtomatik: 24 soatda {$a} ta bot urinishi';
$string['block'] = 'Bloklash';
$string['blockadd'] = 'Manzil yoki diapazonni bloklash';
$string['blockadd_desc'] = 'Hech qachon administratorni yoki oʻz manzilingizni emas. Diapazonlar /16 (IPv4) yoki /32 (IPv6) dan keng boʻlmasligi kerak.';
$string['blockdays'] = 'Muddat';
$string['blockdone'] = 'Bloklangan: {$a}';
$string['blockedtext'] = 'Bu soʻrov xavfsizlik sababli toʻxtatildi. Agar xato deb oʻylasangiz, sayt egasi bilan bogʻlaning.';
$string['blockedtitle'] = 'Soʻrov bloklandi';
$string['blockrefused'] = 'Hech narsa bloklanmadi: qiymat notoʻgʻri, administratorga tegishli yoki oʻz manzilingiz.';
$string['blocks'] = 'Bloklangan manzillar';
$string['blockvalue'] = 'IP yoki diapazon (masalan, 203.0.113.0/24)';
$string['coldata'] = 'Maʻlumotlar';
$string['coldate'] = 'Sana (UTC)';
$string['colemail'] = 'Email';
$string['colip'] = 'Manzil';
$string['colmessage'] = 'Xabar';
$string['colreason'] = 'Sabab';
$string['colsigns'] = 'Belgilar';
$string['coluntil'] = 'Qachongacha (UTC)';
$string['colvalue'] = 'Manzil yoki email';
$string['colverdict'] = 'Xulosa';
$string['colwhere'] = 'Qayerda';
$string['days15'] = '15 kun';
$string['days30'] = '30 kun';
$string['days7'] = '7 kun';
$string['days90'] = '90 kun';
$string['done'] = 'Bajarildi.';
$string['dracoinsomnis:bypassfirewall'] = 'Draco Insomnis firewallni chetlab oʻtish';
$string['events'] = 'Soʻnggi shubhali urinishlar';
$string['events_help'] = '90 kun saqlanadi. Hech qachon passwordlar saqlanmaydi. Manzilning CSV faylida u qilgan hamma narsa bor, tarmoq provayderiga suiisteʻmol haqida xabar berishga ilova qilishga tayyor.';
$string['evidence'] = 'Draco Insomnis: bloklar va dalillar';
$string['forever'] = 'Abadiy';
$string['geo'] = 'Mamlakatlar';
$string['geo_desc'] = 'Tashrif buyuruvchilaringiz koʻp mamlakatlardan kelishi mumkin, hujumchi esa VPN bilan mamlakatni oʻzgartiradi. Faqat kirish, roʻyxatdan oʻtish va shakllarni filtrlang va «Log only» bilan boshlang. Sayt administratorlari, oʻtkazgan odamlaringiz va qidiruv tizimlari hech qachon filtrlanmaydi. Firewall yoqilgan boʻlishi kerak (log yoki bloklash).';
$string['geoaction'] = 'Nima qilish kerak';
$string['geocountries'] = 'Mamlakatlar (ikki harfli kodlar, masalan, ES, FR, DE)';
$string['geocredit'] = 'IP geolokatsiya: DB-IP (db-ip.com, CC BY 4.0), filtrni yoqqaningizda yuklab olinadi va oʻz serveringizda aniqlanadi: hech qanday manzil hech qayerga yuborilmaydi.';
$string['geomode'] = 'Filtr';
$string['geoonly'] = 'Faqat roʻyxatdagi mamlakatlar';
$string['georefuse'] = 'Roʻyxatdagi mamlakatlarni rad etish';
$string['geoscope'] = 'Qayerda';
$string['geosensitive'] = 'Kirish, roʻyxatdan oʻtish va shakllar (tavsiya etiladi)';
$string['geosite'] = 'Butun sayt';
$string['headers'] = 'Xavfsizlik headerlari';
$string['headers_desc'] = 'Sahifalarda: fayl turlarini aniqlash yoʻq, boshqa saytlar tomonidan ramkaga olish yoʻq, kamroq yoʻnaltiruvchi maʻlumot, joylashtirilgan kontent uchun kamera, mikrofon yoki joylashuv yoʻq. Moodle allaqachon yuboradigan header hech qachon yuborilmaydi.';
$string['hsts'] = '6 oy davomida HTTPS ni majburiy qilish (HSTS)';
$string['hsts_desc'] = 'Faqat butun sayt HTTPS da ishlaganda va shunday ishlashda davom etganda: browserlar buni eslab qoladi va muddati tugaguncha oddiy HTTP ni rad etadi.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Soxta roʻyxatdan oʻtishlarni captchasiz toʻxtatadi: botlar hisob ocholmaydi, har bir shubhali urinish esa suiisteʻmol haqida xabar berish uchun dalil sifatida 90 kun saqlanadi. Hujumchiga hech narsa qaytarib yuborilmaydi.</p><p>Bloklangan manzillar va soʻnggi urinishlar: <a href="{$a}">Draco Insomnis: bloklar va dalillar</a>.</p>';
$string['modeblock'] = 'Bloklash';
$string['modelog'] = 'Log only: toʻxtatadigan narsani yozib boradi';
$string['modeoff'] = 'Oʻchiq';
$string['nets'] = 'Ijaraga olingan serverlar tarmoqlari';
$string['nets_desc'] = 'Har bir qatorda bitta diapazon (CIDR), plugin allaqachon biladiganlarga qoʻshiladi. Bu roʻyxatda boʻlish faqat ball qoʻshadi: oʻz-oʻzidan hech kimni botga aylantirmaydi.';
$string['noblocks'] = 'Hozircha hech narsa bloklanmagan.';
$string['noevents'] = 'Hali hech narsa yoʻq.';
$string['noreviews'] = 'Soʻrovlar yoʻq.';
$string['notdone'] = 'Bu manzil uchun buni qilib boʻlmadi.';
$string['pace'] = 'Nusxa koʻchirishga qarshi tezlik cheklovi';
$string['pace_desc'] = 'Bir daqiqada odam oʻqiy oladiganidan koʻp sahifa soʻraganlarga daqiqa tugaguncha «429 Too many requests» beriladi. Kirgan foydalanuvchilar, oʻz manzillaringiz va DNS orqali tasdiqlangan qidiruv tizimlari (Google, Bing, Apple, Yandex) hech qachon cheklanmaydi. AJAX soʻrovlari, veb-xizmatlar va fayllar hisoblanmaydi.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Avtomatik bloklash yoki administrator tomonidan bir muddat bloklangan manzillar va email manzillari.';
$string['privacy:metadata:blocks:value'] = 'Bloklangan IP manzil yoki email.';
$string['privacy:metadata:events'] = 'Shubhali urinishlar (soxta roʻyxatdan oʻtishlar, hujumlar, scraping) suiisteʻmol haqida xabar berish uchun dalil sifatida 90 kun saqlanadi. Moodle hisoblariga bogʻlanmagan. Hech qachon passwordlar saqlanmaydi.';
$string['privacy:metadata:events:fields'] = 'Urinish bilan yuborilgan foydalanuvchi nomi, email va yoʻnaltiruvchi sahifa.';
$string['privacy:metadata:events:ip'] = 'Urinish kelgan IP manzil.';
$string['privacy:metadata:events:timecreated'] = 'Urinish qachon sodir boʻlgan.';
$string['privacy:metadata:events:useragent'] = 'U yuborgan browser yoki dastur nomi.';
$string['proxy'] = 'Tashrif buyuruvchi manzili';
$string['proxy_desc'] = 'Sayt proxy ortida boʻlmasa, «Connection address» ni qoldiring: headerni har kim soxtalashtirishi mumkin.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'Header eʻtiborga olinmaydi: bu ulanish (<code>{$a}</code>) Cloudflare dan yoki ishonchli proxydan kelmagan. Agar proxyingiz internetda boʻlsa, uning manzillarini «Trusted proxies» ga qoʻshing.';
$string['proxynone'] = 'Ulanish manzili (tavsiya etiladi)';
$string['proxyxff'] = 'Boshqa proxy (X-Forwarded-For)';
$string['pwdbreached'] = 'Maʻlumotlar sizib chiqishida topilgan passwordlarni rad etish';
$string['pwdbreached_desc'] = 'Have I Been Pwned xizmatiga k-anonimlik bilan soʻrov yuboradi: saytdan passwordning SHA-1 dagi faqat 5 ta belgisi chiqadi, passwordning oʻzi hech qachon chiqmaydi. Xizmat 3 soniyada javob bermasa, password qabul qilinadi. Moodle buni «Password policy» yoqilgan boʻlsa qoʻllaydi (Site administration > Security > Site security settings).';
$string['pwdbreachedrefused'] = 'Bu password maʻlumotlar sizib chiqishi maʻlum boʻlgan holatlarda uchraydi, shuning uchun hujumchilar uni birinchi sinaydi. Iltimos, boshqasini tanlang.';
$string['pwdmin'] = 'Passwordning minimal uzunligi';
$string['pwdmin_desc'] = '8 dan 64 gacha belgi; 0 boʻlsa, faqat Moodle ning oʻz qoidasi qoladi. «Password policy» yoqilgan boʻlsa qoʻllanadi.';
$string['pwdshort'] = 'Password kamida {$a} ta belgidan iborat boʻlishi kerak.';
$string['rateip'] = 'Bir daqiqada sahifalar, har bir manzil uchun';
$string['ratenet'] = 'Bir daqiqada sahifalar, har bir tarmoq uchun';
$string['ratenet_desc'] = 'IPv4 uchun /24 tarmoq yoki IPv6 uchun /64: scraper yonma-yon manzillarni almashtirib ishlatganda oladigan narsa.';
$string['rejected'] = 'Roʻyxatdan oʻtishni yakunlab boʻlmadi.';
$string['review1'] = '24 soatga oʻtkazish';
$string['review30'] = '30 kun';
$string['review7'] = '7 kun';
$string['reviewapproved'] = 'Oʻtkazish';
$string['reviewattacker'] = 'Hujumchi: bloklangan';
$string['reviewattackerbtn'] = 'Hujumchi';
$string['reviewbody'] = 'Firewall toʻxtatgan tashrif buyuruvchi koʻrib chiqishni soʻraydi. Uni oʻtkazish yoki oʻtkazmaslik uchun Draco Insomnis sahifasini oching.';
$string['reviewbutton'] = 'Koʻrib chiqishni soʻrash';
$string['reviewdenied'] = 'Rad etildi';
$string['reviewdeny'] = 'Rad etish';
$string['reviewemail'] = 'Emailingiz';
$string['reviewmessage'] = 'Nima qilayotgan edingiz?';
$string['reviewreason'] = 'Koʻrib chiqish: {$a}';
$string['reviews'] = 'Koʻrib chiqish soʻrovlari';
$string['reviewsenttext'] = 'Rahmat. Sayt egasi buni koʻrib chiqadi va agar xato boʻlsa, sizni oʻtkazadi.';
$string['reviewsenttitle'] = 'Soʻrov yuborildi';
$string['reviewshelp'] = 'Firewall toʻxtatgan odamlar blok sahifasidan soʻrashi mumkin. Agar xato boʻlsa, ularni bir muddat oʻtkazing. Draco ularga hech qachon yozmaydi: xohlasangiz, oʻz mailingizdan javob bering.';
$string['reviewsubject'] = '[{$a}] Kimdir firewall blokini koʻrib chiqishingizni soʻraydi';
$string['shield'] = 'Oʻz-oʻzini roʻyxatdan oʻtkazishni himoya qilish';
$string['shield_desc'] = 'Roʻyxatdan oʻtish shakliga (email orqali oʻz-oʻzini roʻyxatdan oʻtkazish) koʻrinmas tuzoq va imzolangan sahifa muhrini qoʻshadi. Botlar hisob ocholmaydi; bir kunda uchta bot urinishi manzilni bir haftaga bloklaydi.';
$string['summary'] = 'Firewall: soʻnggi 7 kun';
$string['summaryips'] = 'Eng faol manzillar:';
$string['summaryline'] = '{$a->total} ta hujum aniqlandi, {$a->blocked} tasi bloklandi.';
$string['summarywhat'] = 'Nima:';
$string['taskcleanup'] = 'Draco Insomnis: eski dalillar va tugagan bloklarni oʻchirish';
$string['test'] = 'Firewallni sinash';
$string['testblocked'] = 'Ishlaydi: maʻlumotlar bazasiga inyeksiya tanildi va bloklandi (403).';
$string['testhelp'] = 'Saytga zararsiz, hujumga oʻxshash soʻrov yuboradi va nima boʻlganini aytadi. U logga yozilmaydi.';
$string['testlogged'] = 'Ishlaydi: maʻlumotlar bazasiga inyeksiya tanildi. «Log only» rejimida u yozib boriladi, lekin toʻxtatilmaydi; tayyor boʻlganingizda «Bloklash» ga oʻting.';
$string['testnone'] = 'Sinov hujumi tanilmadi. Iltimos, bu haqda Draco Insomnisga xabar bering.';
$string['testoff'] = 'Firewall oʻchiq: uni yoqing va saqlang, keyin yana sinang.';
$string['testunreachable'] = 'Sinov serverning oʻzidan saytga yeta olmadi (baʻzi hostinglar bunga ruxsat bermaydi). Firewall baribir ishlashi mumkin: soʻnggi urinishlarga qarang.';
$string['testupstream'] = 'Sinov Moodle ga yetmasdan, hostingning oʻz firewall tomonidan toʻxtatildi. Yaxshi: ikki qatlam.';
$string['trusted'] = 'Ishonchli proxy-serverlar';
$string['trusted_desc'] = 'Faqat shu manzillardan kelgan ulanishlar header orqali tashrif buyuruvchi manzilini belgilashi mumkin. Har bir qatorda bitta manzil yoki diapazon. Boʻsh boʻlsa: shu server va shaxsiy tarmoqlar. Cloudflare ning oʻz diapazonlari allaqachon maʻlum.';
$string['unblock'] = 'Blokdan chiqarish';
$string['unblocked'] = 'Manzil blokdan chiqarildi.';
$string['waf'] = 'Firewall';
$string['waf_desc'] = 'Hujum shaklidagi soʻrovlarni (maʻlumotlar bazasiga inyeksiya, server fayllarini oʻqish, kod ishga tushirish, havolalardagi skriptlar) va sqlmap yoki Nikto kabi skanerlarni toʻxtatadi. «Log only» bilan boshlang va bir necha kundan keyin «Bloklash» ga oʻting. 10 daqiqada beshta hujum manzilni bir haftaga bloklaydi; bloklangan manzillar saytni oʻqishda davom etishi mumkin, lekin hech narsa yubora olmaydi va kira olmaydi. Sayt administratorlari va «Draco Insomnis firewallni chetlab oʻtish» huquqiga ega foydalanuvchilar hech qachon tekshirilmaydi. Favqulodda chiqish: define(\'DRACO_WAF_OFF\', true); config.php faylida.';
$string['wafblock'] = 'Firewall: 10 daqiqada {$a} ta hujum';
$string['yourip'] = 'Plagin koʻrayotgan manzilingiz: <code>{$a->ip}</code> (ulanish manzili: <code>{$a->remote}</code>). Agar sayt Cloudflare yoki boshqa proxy ortida boʻlsa va bular haqiqiy manzilingizdan farq qilsa, «Visitor address» boʻlimida mos variantni tanlang.';
