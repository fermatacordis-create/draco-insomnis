<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'tl' (generated from i18n/tl.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Awtomatiko: {$a} pagtatangka ng bot sa loob ng 24 oras';
$string['block'] = 'Harangan';
$string['blockadd'] = 'Harangan ang isang address o saklaw';
$string['blockadd_desc'] = 'Hindi kailanman ang administrator, at hindi rin ang sarili mong address. Mga saklaw na hindi lalawak sa /16 (IPv4) o /32 (IPv6).';
$string['blockdays'] = 'Tagal';
$string['blockdone'] = 'Hinarangan: {$a}';
$string['blockedtext'] = 'Pinigilan ang kahilingang ito dahil sa seguridad. Kung sa tingin mo ay pagkakamali ito, makipag-ugnayan sa may-ari ng site.';
$string['blockedtitle'] = 'Hinarang ang kahilingan';
$string['blockrefused'] = 'Walang hinarang: hindi wasto ang halaga, pag-aari ng isang administrator, o ang sarili mong address.';
$string['blocks'] = 'Mga hinarangang address';
$string['blockvalue'] = 'IP o saklaw (hal. 203.0.113.0/24)';
$string['coldata'] = 'Datos';
$string['coldate'] = 'Petsa (UTC)';
$string['colemail'] = 'Email';
$string['colip'] = 'Address';
$string['colmessage'] = 'Mensahe';
$string['colreason'] = 'Dahilan';
$string['colsigns'] = 'Mga palatandaan';
$string['coluntil'] = 'Hanggang (UTC)';
$string['colvalue'] = 'Address o email';
$string['colverdict'] = 'Hatol';
$string['colwhere'] = 'Saan';
$string['days15'] = '15 araw';
$string['days30'] = '30 araw';
$string['days7'] = '7 araw';
$string['days90'] = '90 araw';
$string['done'] = 'Tapos na.';
$string['dracoinsomnis:bypassfirewall'] = 'Lampasan ang firewall ng Draco Insomnis';
$string['events'] = 'Mga huling kahina-hinalang pagtatangka';
$string['events_help'] = 'Iniimbak nang 90 araw. Hindi kailanman password. Ang CSV ng isang address ay may lahat ng ginawa nito, handang ilakip sa ulat ng pang-aabuso sa provider ng network nito.';
$string['evidence'] = 'Draco Insomnis: mga harang at ebidensya';
$string['forever'] = 'Magpakailanman';
$string['geo'] = 'Mga bansa';
$string['geo_desc'] = 'Maaaring galing sa maraming bansa ang mga bisita mo, at nagpapalit ng bansa ang umaatake gamit ang VPN. Salain lang ang pag-log in, pagpaparehistro at mga form, at magsimula sa “Itala lang”. Hindi kailanman sinasala ang mga administrator ng site, ang mga taong pinadaan mo at ang mga search engine. Kailangang naka-on ang firewall (itala o harangan).';
$string['geoaction'] = 'Ano ang gagawin';
$string['geocountries'] = 'Mga bansa (dalawang-titik na code, hal. ES, FR, DE)';
$string['geocredit'] = 'IP geolocation mula sa DB-IP (db-ip.com, CC BY 4.0), dina-download kapag in-on mo ang filter at hinahanap sa sarili mong server: walang address na ipinapadala kahit saan.';
$string['geomode'] = 'Filter';
$string['geoonly'] = 'Ang mga nakalistang bansa lang';
$string['georefuse'] = 'Tanggihan ang mga nakalistang bansa';
$string['geoscope'] = 'Saan';
$string['geosensitive'] = 'Pag-login, pagpaparehistro at mga form (inirerekomenda)';
$string['geosite'] = 'Ang buong site';
$string['headers'] = 'Mga header ng seguridad';
$string['headers_desc'] = 'Sa mga pahina: walang panghuhula ng uri ng file, walang pag-embed sa ibang site, mas kaunting datos ng pinanggalingan, walang camera, mikropono o lokasyon para sa naka-embed na nilalaman. Hindi kailanman ang header na ipinapadala na ng Moodle.';
$string['hsts'] = 'Pilitin ang HTTPS nang 6 na buwan (HSTS)';
$string['hsts_desc'] = 'Kapag gumagana lang ang buong site sa HTTPS at patuloy na gagana: tinatandaan ito ng mga browser at tinatanggihan ang HTTP hanggang mag-expire.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Pinipigilan ang mga pekeng pagpaparehistro nang walang captcha: hindi nakakakuha ng account ang mga bot, at bawat kahina-hinalang pagtatangka ay iniimbak nang 90 araw bilang ebidensya para sa ulat ng pang-aabuso. Walang anumang ibinabalik sa umaatake.</p><p>Mga hinarangang address at huling pagtatangka: <a href="{$a}">Draco Insomnis: mga harang at ebidensya</a>.</p>';
$string['modeblock'] = 'Harangan';
$string['modelog'] = 'Itala lang: itala ang mapipigilan sana';
$string['modeoff'] = 'Patay';
$string['nets'] = 'Mga network ng inuupahang server';
$string['nets_desc'] = 'Isang saklaw bawat linya (CIDR), idinadagdag sa mga alam na ng plugin. Ang pagiging nasa listahang ito ay nagdadagdag lang ng puntos: mag-isa, hindi nito ginagawang bot ang sinuman.';
$string['noblocks'] = 'Walang naka-harang sa ngayon.';
$string['noevents'] = 'Wala pa.';
$string['noreviews'] = 'Walang kahilingan.';
$string['notdone'] = 'Hindi ito magawa para sa address na iyon.';
$string['pace'] = 'Limitasyon sa bilis laban sa pangongopya';
$string['pace_desc'] = 'Ang humihingi ng mas maraming pahina bawat minuto kaysa sa nababasa ng tao ay makakatanggap ng “429 Too many requests” hanggang matapos ang minuto. Hindi kailanman nililimitahan ang mga naka-log in na user, ang sarili mong mga address at ang mga search engine na beripikado sa DNS (Google, Bing, Apple, Yandex). Hindi binibilang ang mga tawag ng AJAX, mga web service at mga file.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Mga address at email na hinarangan nang ilang panahon, ng awtomatikong harang o ng administrator.';
$string['privacy:metadata:blocks:value'] = 'Ang hinarangang IP address o email.';
$string['privacy:metadata:events'] = 'Mga kahina-hinalang pagtatangka (pekeng pagpaparehistro, atake, scraping), iniimbak nang 90 araw bilang ebidensya para sa mga ulat ng pang-aabuso. Hindi naka-link sa mga account ng Moodle. Hindi kailanman password.';
$string['privacy:metadata:events:fields'] = 'Username, email at pahinang pinanggalingan na ipinadala kasama ng pagtatangka.';
$string['privacy:metadata:events:ip'] = 'Ang IP address na pinanggalingan ng pagtatangka.';
$string['privacy:metadata:events:timecreated'] = 'Kailan nangyari ang pagtatangka.';
$string['privacy:metadata:events:useragent'] = 'Ang pangalan ng browser o programang ipinadala nito.';
$string['proxy'] = 'Address ng bisita';
$string['proxy_desc'] = 'Iwanan ang “Address ng koneksyon” maliban kung nasa likod ng proxy ang site: kayang pekein ninuman ang isang header.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'Hindi pinapansin ang header: ang koneksyong ito (<code>{$a}</code>) ay hindi galing sa Cloudflare o sa pinagkakatiwalaang proxy. Kung nasa internet ang proxy mo, idagdag ang mga address nito sa “Mga pinagkakatiwalaang proxy”.';
$string['proxynone'] = 'Address ng koneksyon (inirerekomenda)';
$string['proxyxff'] = 'Ibang proxy (X-Forwarded-For)';
$string['pwdbreached'] = 'Tanggihan ang mga password na nakita sa mga data breach';
$string['pwdbreached_desc'] = 'Nagtatanong sa Have I Been Pwned gamit ang k-anonymity: 5 karakter lang ng SHA-1 ng password ang lumalabas sa site, hindi kailanman ang password. Kung hindi sumagot ang serbisyo sa loob ng 3 segundo, tinatanggap ang password. Ipinapatupad ito ng Moodle habang naka-on ang “Password policy” (Site administration > Security > Site security settings).';
$string['pwdbreachedrefused'] = 'Lumalabas ang password na ito sa mga kilalang data breach, kaya ito ang unang sinusubukan ng mga umaatake. Pumili ng iba, pakiusap.';
$string['pwdmin'] = 'Pinakamaikling haba ng password';
$string['pwdmin_desc'] = 'Mula 8 hanggang 64 na karakter; ang 0 ay nag-iiwan lang ng sariling patakaran ng Moodle. Ipinapatupad habang naka-on ang “Password policy”.';
$string['pwdshort'] = 'Dapat may hindi bababa sa {$a} karakter ang password.';
$string['rateip'] = 'Mga pahina bawat minuto, bawat address';
$string['ratenet'] = 'Mga pahina bawat minuto, bawat network';
$string['ratenet_desc'] = 'Isang /24 na network sa IPv4 o /64 sa IPv6: ang nakukuha ng scraper kapag nagpapalit-palit ng magkakatabing address.';
$string['rejected'] = 'Hindi makumpleto ang pagpaparehistro.';
$string['review1'] = 'Padaanin nang 24 na oras';
$string['review30'] = '30 araw';
$string['review7'] = '7 araw';
$string['reviewapproved'] = 'Padaanin';
$string['reviewattacker'] = 'Umaatake: hinarang';
$string['reviewattackerbtn'] = 'Umaatake';
$string['reviewbody'] = 'Humihingi ng pagsusuri ang isang bisitang pinigilan ng firewall. Buksan ang pahina ng Draco Insomnis para padaanin siya o hindi.';
$string['reviewbutton'] = 'Humiling ng pagsusuri';
$string['reviewdenied'] = 'Tinanggihan';
$string['reviewdeny'] = 'Tanggihan';
$string['reviewemail'] = 'Ang email mo';
$string['reviewmessage'] = 'Ano ang ginagawa mo?';
$string['reviewreason'] = 'Pagsusuri: {$a}';
$string['reviews'] = 'Mga kahilingan sa pagsusuri';
$string['reviewsenttext'] = 'Salamat. Titingnan ito ng may-ari ng site at, kung pagkakamali ito, padaraanin ka.';
$string['reviewsenttitle'] = 'Naipadala ang kahilingan';
$string['reviewshelp'] = 'Maaaring humiling mula sa pahina ng harang ang mga pinigilan ng firewall. Padaanin sila nang ilang panahon kung pagkakamali ito. Hindi kailanman sumusulat sa kanila ang Draco: sagutin mula sa sarili mong mail kung gusto mo.';
$string['reviewsubject'] = '[{$a}] May humihiling na suriin mo ang isang harang ng firewall';
$string['shield'] = 'Protektahan ang sariling pagpaparehistro';
$string['shield_desc'] = 'Nagdadagdag ng di-nakikitang bitag at pinirmahang tatak ng pahina sa form ng pagpaparehistro (sariling pagpaparehistro sa email). Walang account ang mga bot; tatlong pagtatangka ng bot sa isang araw ay haharang sa address nang isang linggo.';
$string['summary'] = 'Firewall: huling 7 araw';
$string['summaryips'] = 'Pinakaaktibong address:';
$string['summaryline'] = '{$a->total} atake ang nakita, {$a->blocked} ang hinarangan.';
$string['summarywhat'] = 'Ano:';
$string['taskcleanup'] = 'Draco Insomnis: alisin ang lumang ebidensya at mga tapos nang harang';
$string['test'] = 'Subukan ang firewall';
$string['testblocked'] = 'Gumagana: may nakilalang injection sa database at hinarang ito (403).';
$string['testhelp'] = 'Nagpapadala sa site ng di-mapanganib na kahilingang mukhang pag-atake at sinasabi sa iyo ang nangyari. Hindi ito itinatala.';
$string['testlogged'] = 'Gumagana: may nakilalang injection sa database. Sa "Itala lang" ay isinusulat ito pero hindi pinipigilan; lumipat sa "Harangan" kapag handa ka na.';
$string['testnone'] = 'Hindi nakilala ang pagsubok na pag-atake. Pakiulat ito sa Draco Insomnis.';
$string['testoff'] = 'Patay ang firewall: buksan ito, i-save, at subukang muli.';
$string['testunreachable'] = 'Hindi maabot ng pagsubok ang site mula sa mismong server (may mga hosting na hindi ito pinapayagan). Maaaring gumagana pa rin ang firewall: tingnan ang mga huling pagtatangka.';
$string['testupstream'] = 'Napigilan ang pagsubok bago umabot sa Moodle, ng sariling firewall ng hosting. Mabuti: dalawang patong.';
$string['trusted'] = 'Mga pinagkakatiwalaang proxy';
$string['trusted_desc'] = 'Ang mga koneksyon lang mula sa mga address na ito ang puwedeng magtakda ng address ng bisita sa pamamagitan ng header. Isang address o saklaw bawat linya. Walang laman: ang server na ito at mga pribadong network. Alam na ang sariling mga saklaw ng Cloudflare.';
$string['unblock'] = 'Alisin ang harang';
$string['unblocked'] = 'Inalis ang harang sa address.';
$string['waf'] = 'Firewall';
$string['waf_desc'] = 'Pinipigilan ang mga request na hugis-atake (injection sa database, pagbasa ng mga file ng server, pagpapatakbo ng code, script sa mga link) at mga scanner tulad ng sqlmap o Nikto. Magsimula sa “Itala lang” at lumipat sa “Harangan” makalipas ang ilang araw. Limang atake sa loob ng 10 minuto ay haharang sa address nang isang linggo; makakabasa pa rin ng site ang mga hinarangang address, pero hindi makakapagpadala o makakapag-log in. Hindi kailanman sinusuri ang mga administrator ng site at ang mga user na may “Lampasan ang firewall ng Draco Insomnis”. Emergency na labasan: define(\'DRACO_WAF_OFF\', true); sa config.php.';
$string['wafblock'] = 'Firewall: {$a} atake sa loob ng 10 minuto';
$string['yourip'] = 'Ang address mo ayon sa nakikita ng plugin: <code>{$a->ip}</code> (address ng koneksyon: <code>{$a->remote}</code>). Kung ang site ay nasa likod ng Cloudflare o ibang proxy at iba ang mga ito sa totoong address mo, piliin ang katugmang opsyon sa “Address ng bisita”.';
