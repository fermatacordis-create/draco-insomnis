<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'tr' (generated from i18n/tr.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Otomatik: 24 saatte {$a} bot denemesi';
$string['block'] = 'Engelle';
$string['blockadd'] = 'Bir adresi veya aralığı engelle';
$string['blockadd_desc'] = 'Asla bir yönetici ya da kendi adresiniz değil. Aralıklar /16 (IPv4) veya /32 (IPv6) değerinden geniş olamaz.';
$string['blockdays'] = 'Süre';
$string['blockdone'] = 'Engellendi: {$a}';
$string['blockedtext'] = 'Bu istek güvenlik nedeniyle durduruldu. Bunun bir hata olduğunu düşünüyorsanız site sahibiyle iletişime geçin.';
$string['blockedtitle'] = 'İstek engellendi';
$string['blockrefused'] = 'Hiçbir şey engellenmedi: değer geçersiz, bir yöneticiye ait ya da sizin adresiniz.';
$string['blocks'] = 'Engellenen adresler';
$string['blockvalue'] = 'IP veya aralık (ör. 203.0.113.0/24)';
$string['coldata'] = 'Veriler';
$string['coldate'] = 'Tarih (UTC)';
$string['colemail'] = 'E-posta';
$string['colip'] = 'Adres';
$string['colmessage'] = 'Mesaj';
$string['colreason'] = 'Neden';
$string['colsigns'] = 'İşaretler';
$string['coluntil'] = 'Bitiş (UTC)';
$string['colvalue'] = 'Adres veya e-posta';
$string['colverdict'] = 'Karar';
$string['colwhere'] = 'Nerede';
$string['days15'] = '15 gün';
$string['days30'] = '30 gün';
$string['days7'] = '7 gün';
$string['days90'] = '90 gün';
$string['done'] = 'Tamam.';
$string['dracoinsomnis:bypassfirewall'] = 'Draco Insomnis güvenlik duvarını atla';
$string['events'] = 'Son şüpheli denemeler';
$string['events_help'] = '90 gün saklanır. Asla parola tutulmaz. Bir adresin CSV dosyası yaptığı her şeyi içerir; ağ sağlayıcısına yapılacak kötüye kullanım bildirimine eklemeye hazırdır.';
$string['evidence'] = 'Draco Insomnis: engeller ve kanıtlar';
$string['forever'] = 'Süresiz';
$string['geo'] = 'Ülkeler';
$string['geo_desc'] = 'Ziyaretçileriniz birçok ülkeden gelebilir ve bir saldırgan VPN ile ülke değiştirir. Yalnızca giriş, kayıt ve formları filtreleyin ve “Yalnızca kaydet” ile başlayın. Site yöneticileri, geçirdiğiniz kişiler ve arama motorları asla filtrelenmez. Güvenlik duvarının açık olması gerekir (kaydet veya engelle).';
$string['geoaction'] = 'Ne yapılsın';
$string['geocountries'] = 'Ülkeler (iki harfli kodlar, ör. ES, FR, DE)';
$string['geocredit'] = 'IP konum bilgisi DB-IP’den (db-ip.com, CC BY 4.0); filtreyi açtığınızda indirilir ve kendi sunucunuzda sorgulanır: hiçbir adres hiçbir yere gönderilmez.';
$string['geomode'] = 'Filtre';
$string['geoonly'] = 'Yalnızca listedeki ülkeler';
$string['georefuse'] = 'Listedeki ülkeleri reddet';
$string['geoscope'] = 'Nerede';
$string['geosensitive'] = 'Giriş, kayıt ve formlar (önerilen)';
$string['geosite'] = 'Tüm site';
$string['headers'] = 'Güvenlik başlıkları';
$string['headers_desc'] = 'Sayfalarda: dosya türü tahmini yok, başka sitelere gömülme yok, daha az kaynak verisi, gömülü içerik için kamera, mikrofon veya konum yok. Moodle’ın zaten gönderdiği bir başlık asla tekrar gönderilmez.';
$string['hsts'] = 'HTTPS’i 6 ay zorunlu kıl (HSTS)';
$string['hsts_desc'] = 'Yalnızca tüm site HTTPS ile çalışıyorsa ve öyle kalacaksa: tarayıcılar bunu hatırlar ve süre dolana kadar HTTP\'yi reddeder.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Captcha olmadan sahte kayıtları durdurur: botlar hesap alamaz ve her şüpheli deneme kötüye kullanım bildirimi için kanıt olarak 90 gün saklanır. Saldırgana asla bir şey geri gönderilmez.</p><p>Engellenen adresler ve son denemeler: <a href="{$a}">Draco Insomnis: engeller ve kanıtlar</a>.</p>';
$string['modeblock'] = 'Engelle';
$string['modelog'] = 'Yalnızca kaydet: durduracağı şeyi not al';
$string['modeoff'] = 'Kapalı';
$string['nets'] = 'Kiralık sunucu ağları';
$string['nets_desc'] = 'Her satıra bir aralık (CIDR); eklentinin zaten bildiklerine eklenir. Bu listede olmak yalnızca puan ekler: tek başına kimseyi bot yapmaz.';
$string['noblocks'] = 'Şu anda engellenen bir şey yok.';
$string['noevents'] = 'Henüz bir şey yok.';
$string['noreviews'] = 'İstek yok.';
$string['notdone'] = 'Bu adres için yapılamadı.';
$string['pace'] = 'Kopyalamaya karşı hız sınırı';
$string['pace_desc'] = 'Bir insanın okuyabileceğinden fazla sayfayı dakikada isteyen, dakika bitene kadar “429 Too many requests” alır. Oturum açmış kullanıcılar, kendi adresleriniz ve DNS ile doğrulanmış arama motorları (Google, Bing, Apple, Yandex) asla sınırlanmaz. AJAX çağrıları, web hizmetleri ve dosyalar sayılmaz.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Otomatik engelleme veya bir yönetici tarafından bir süreliğine engellenen adresler ve e-postalar.';
$string['privacy:metadata:blocks:value'] = 'Engellenen IP adresi veya e-posta.';
$string['privacy:metadata:events'] = 'Şüpheli denemeler (sahte kayıtlar, saldırılar, toplu kopyalama), kötüye kullanım bildirimleri için kanıt olarak 90 gün saklanır. Moodle hesaplarıyla ilişkilendirilmez. Asla parola tutulmaz.';
$string['privacy:metadata:events:fields'] = 'Denemeyle gönderilen kullanıcı adı, e-posta ve yönlendiren sayfa.';
$string['privacy:metadata:events:ip'] = 'Denemenin geldiği IP adresi.';
$string['privacy:metadata:events:timecreated'] = 'Denemenin gerçekleştiği zaman.';
$string['privacy:metadata:events:useragent'] = 'Gönderdiği tarayıcı veya program adı.';
$string['proxy'] = 'Ziyaretçi adresi';
$string['proxy_desc'] = 'Site bir proxy arkasında değilse “Bağlantı adresi”ni bırakın: bir başlığı herkes taklit edebilir.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'Başlık yok sayılıyor: bu bağlantı (<code>{$a}</code>) Cloudflare’den ya da güvenilen bir proxy’den gelmiyor. Proxy’niz internetteyse adreslerini “Güvenilen proxy’ler” bölümüne ekleyin.';
$string['proxynone'] = 'Bağlantı adresi (önerilir)';
$string['proxyxff'] = 'Diğer proxy (X-Forwarded-For)';
$string['pwdbreached'] = 'Veri sızıntılarında bulunan parolaları reddet';
$string['pwdbreached_desc'] = 'Have I Been Pwned’e k-anonimlikle sorar: siteden parolanın SHA-1 değerinin yalnızca 5 karakteri çıkar, parolanın kendisi asla. Hizmet 3 saniye içinde yanıt vermezse parola kabul edilir. Moodle bunu “Parola politikası” açık olduğu sürece uygular (Site yönetimi > Güvenlik > Site güvenlik ayarları).';
$string['pwdbreachedrefused'] = 'Bu parola bilinen veri sızıntılarında geçiyor, bu yüzden saldırganlar önce onu dener. Lütfen başka bir parola seçin.';
$string['pwdmin'] = 'En kısa parola uzunluğu';
$string['pwdmin_desc'] = '8 ile 64 karakter arası; 0 yalnızca Moodle’ın kendi kuralını bırakır. “Parola politikası” açık olduğu sürece uygulanır.';
$string['pwdshort'] = 'Parola en az {$a} karakter olmalıdır.';
$string['rateip'] = 'Adres başına dakikada sayfa';
$string['ratenet'] = 'Ağ başına dakikada sayfa';
$string['ratenet_desc'] = 'IPv4 için /24, IPv6 için /64 ağ: komşu adresler arasında dolaşan bir kazıyıcının elde ettiği alan.';
$string['rejected'] = 'Kayıt tamamlanamadı.';
$string['review1'] = '24 saat geçir';
$string['review30'] = '30 gün';
$string['review7'] = '7 gün';
$string['reviewapproved'] = 'Geçir';
$string['reviewattacker'] = 'Saldırgan: engellendi';
$string['reviewattackerbtn'] = 'Saldırgan';
$string['reviewbody'] = 'Güvenlik duvarının durdurduğu bir ziyaretçi inceleme istiyor. Geçirip geçirmemeye karar vermek için Draco Insomnis sayfasını açın.';
$string['reviewbutton'] = 'İnceleme iste';
$string['reviewdenied'] = 'Reddedildi';
$string['reviewdeny'] = 'Reddet';
$string['reviewemail'] = 'E-postanız';
$string['reviewmessage'] = 'Ne yapıyordunuz?';
$string['reviewreason'] = 'İnceleme: {$a}';
$string['reviews'] = 'İnceleme istekleri';
$string['reviewsenttext'] = 'Teşekkürler. Site sahibi inceleyecek ve bir hataysa geçmenize izin verecek.';
$string['reviewsenttitle'] = 'İstek gönderildi';
$string['reviewshelp'] = 'Güvenlik duvarının durdurduğu kişiler engel sayfasından isteyebilir. Bir hataysa bir süre geçmelerine izin verin. Draco onlara asla yazmaz: isterseniz kendi e-postanızdan yanıtlayın.';
$string['reviewsubject'] = '[{$a}] Birisi bir güvenlik duvarı engelini incelemenizi istiyor';
$string['shield'] = 'Kendi kendine kaydı koru';
$string['shield_desc'] = 'Kayıt formuna (e-posta ile kendi kendine kayıt) görünmez bir tuzak ve imzalı bir sayfa damgası ekler. Botlar hesap alamaz; bir günde üç bot denemesi adresi bir hafta engeller.';
$string['summary'] = 'Güvenlik duvarı: son 7 gün';
$string['summaryips'] = 'En hareketli adresler:';
$string['summaryline'] = '{$a->total} saldırı görüldü, {$a->blocked} engellendi.';
$string['summarywhat'] = 'Ne:';
$string['taskcleanup'] = 'Draco Insomnis: eski kanıtları ve süresi dolan engelleri kaldır';
$string['test'] = 'Güvenlik duvarını test et';
$string['testblocked'] = 'Çalışıyor: bir veritabanı enjeksiyonu tanındı ve engellendi (403).';
$string['testhelp'] = 'Siteye saldırı biçiminde zararsız bir istek gönderir ve ne olduğunu söyler. Kaydedilmez.';
$string['testlogged'] = 'Çalışıyor: bir veritabanı enjeksiyonu tanındı. «Yalnızca kaydet» modunda not edilir ama durdurulmaz; hazır olduğunuzda «Engelle»ye geçin.';
$string['testnone'] = 'Test saldırısı tanınmadı. Lütfen Draco Insomnis\'e bildirin.';
$string['testoff'] = 'Güvenlik duvarı kapalı: açın, kaydedin ve yeniden deneyin.';
$string['testunreachable'] = 'Test, sunucunun kendisinden siteye ulaşamadı (bazı barındırma hizmetleri buna izin vermez). Güvenlik duvarı yine de çalışıyor olabilir: son denemelere bakın.';
$string['testupstream'] = 'Test, Moodle’a ulaşmadan barındırma hizmetinin kendi güvenlik duvarında durduruldu. İyi: iki katman.';
$string['trusted'] = 'Güvenilen proxy’ler';
$string['trusted_desc'] = 'Ziyaretçi adresini bir başlıkla yalnızca bu adreslerden gelen bağlantılar belirleyebilir. Her satıra bir adres veya aralık. Boş: bu sunucu ve özel ağlar. Cloudflare’in kendi aralıkları zaten biliniyor.';
$string['unblock'] = 'Engeli kaldır';
$string['unblocked'] = 'Adresin engeli kaldırıldı.';
$string['waf'] = 'Güvenlik duvarı';
$string['waf_desc'] = 'Saldırı biçimindeki istekleri (veritabanı enjeksiyonu, sunucu dosyalarını okuma, kod çalıştırma, bağlantılarda betik) ve sqlmap ya da Nikto gibi tarayıcıları durdurur. “Yalnızca kaydet” ile başlayın ve birkaç gün sonra “Engelle”ye geçin. 10 dakikada beş saldırı adresi bir hafta engeller; engellenen adresler siteyi okumaya devam edebilir ama bir şey gönderemez ve oturum açamaz. Site yöneticileri ve “Draco Insomnis güvenlik duvarını atla” yetkisi olan kullanıcılar asla denetlenmez. Acil çıkış: config.php dosyasına define(\'DRACO_WAF_OFF\', true); ekleyin.';
$string['wafblock'] = 'Güvenlik duvarı: 10 dakikada {$a} saldırı';
$string['yourip'] = 'Eklentinin gördüğü adresiniz: <code>{$a->ip}</code> (bağlantı adresi: <code>{$a->remote}</code>). Site Cloudflare veya başka bir proxy arkasındaysa ve bunlar gerçek adresinizden farklıysa, “Ziyaretçi adresi” bölümünde uygun seçeneği seçin.';
