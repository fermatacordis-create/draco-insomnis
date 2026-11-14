<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'de' (generated from i18n/de.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Automatisch: {$a} Bot-Versuche in 24 h';
$string['block'] = 'Blockieren';
$string['blockadd'] = 'Eine Adresse oder einen Bereich sperren';
$string['blockadd_desc'] = 'Nie ein Administrator und nie Ihre eigene Adresse. Bereiche nicht größer als /16 (IPv4) oder /32 (IPv6).';
$string['blockdays'] = 'Für';
$string['blockdone'] = 'Gesperrt: {$a}';
$string['blockedtext'] = 'Diese Anfrage wurde aus Sicherheitsgründen gestoppt. Wenn du denkst, dass das ein Fehler ist, wende dich an den Betreiber der Website.';
$string['blockedtitle'] = 'Anfrage blockiert';
$string['blockrefused'] = 'Nichts wurde blockiert: Der Wert ist ungültig, gehört einem Administrator oder ist deine eigene Adresse.';
$string['blocks'] = 'Gesperrte Adressen';
$string['blockvalue'] = 'IP oder Bereich (z. B. 203.0.113.0/24)';
$string['coldata'] = 'Daten';
$string['coldate'] = 'Datum (UTC)';
$string['colemail'] = 'E-Mail';
$string['colip'] = 'Adresse';
$string['colmessage'] = 'Nachricht';
$string['colreason'] = 'Grund';
$string['colsigns'] = 'Anzeichen';
$string['coluntil'] = 'Bis (UTC)';
$string['colvalue'] = 'Adresse oder E-Mail';
$string['colverdict'] = 'Urteil';
$string['colwhere'] = 'Wo';
$string['days15'] = '15 Tage';
$string['days30'] = '30 Tage';
$string['days7'] = '7 Tage';
$string['days90'] = '90 Tage';
$string['done'] = 'Erledigt.';
$string['dracoinsomnis:bypassfirewall'] = 'Die Firewall von Draco Insomnis umgehen';
$string['events'] = 'Letzte verdächtige Versuche';
$string['events_help'] = '90 Tage aufbewahrt. Niemals Passwörter. Die CSV einer Adresse enthält alles, was sie getan hat, bereit zum Anhängen an eine Missbrauchsmeldung an ihren Netzanbieter.';
$string['evidence'] = 'Draco Insomnis: Sperren und Beweise';
$string['forever'] = 'Für immer';
$string['geo'] = 'Länder';
$string['geo_desc'] = 'Ihre Besucher können aus vielen Ländern kommen, und ein Angreifer wechselt das Land mit einem VPN. Filtern Sie nur Anmeldung, Registrierung und Formulare, und beginnen Sie mit „Nur protokollieren“. Website-Administratoren, Personen, die Sie durchlassen, und Suchmaschinen werden nie gefiltert. Die Firewall muss an sein (protokollieren oder blockieren).';
$string['geoaction'] = 'Was tun';
$string['geocountries'] = 'Länder (Zwei-Buchstaben-Codes, z. B. ES, FR, DE)';
$string['geocredit'] = 'IP-Geolokalisierung von DB-IP (db-ip.com, CC BY 4.0), heruntergeladen, wenn Sie den Filter einschalten, und auf Ihrem eigenen Server abgefragt: Keine Adresse wird irgendwohin gesendet.';
$string['geomode'] = 'Filter';
$string['geoonly'] = 'Nur die aufgelisteten Länder';
$string['georefuse'] = 'Aufgelistete Länder ablehnen';
$string['geoscope'] = 'Wo';
$string['geosensitive'] = 'Anmeldung, Registrierung und Formulare (empfohlen)';
$string['geosite'] = 'Die ganze Website';
$string['headers'] = 'Sicherheits-Header';
$string['headers_desc'] = 'Auf Seiten: kein Erraten von Dateitypen, keine Einbettung in fremde Websites, weniger Herkunftsdaten, keine Kamera, kein Mikrofon und kein Standort für eingebettete Inhalte. Nie einer, den Moodle schon sendet.';
$string['hsts'] = 'HTTPS für 6 Monate erzwingen (HSTS)';
$string['hsts_desc'] = 'Nur wenn die ganze Website über HTTPS läuft und das so bleibt: Browser merken es sich und lehnen HTTP ab, bis es abläuft.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Stoppt gefälschte Registrierungen ohne Captchas: Bots bekommen kein Konto, und jeder verdächtige Versuch wird 90 Tage als Beweis für eine Missbrauchsmeldung aufbewahrt. Dem Angreifer wird nie etwas zurückgeschickt.</p><p>Gesperrte Adressen und letzte Versuche: <a href="{$a}">Draco Insomnis: Sperren und Beweise</a>.</p>';
$string['modeblock'] = 'Blockieren';
$string['modelog'] = 'Nur protokollieren: festhalten, was gestoppt würde';
$string['modeoff'] = 'Aus';
$string['nets'] = 'Netze gemieteter Server';
$string['nets_desc'] = 'Ein Bereich pro Zeile (CIDR), zusätzlich zu denen, die das Plugin schon kennt. Auf dieser Liste zu stehen gibt nur Punkte: Allein macht sie niemanden zum Bot.';
$string['noblocks'] = 'Derzeit ist nichts gesperrt.';
$string['noevents'] = 'Noch nichts.';
$string['noreviews'] = 'Keine Anfragen.';
$string['notdone'] = 'Für diese Adresse war es nicht möglich.';
$string['pace'] = 'Anti-Kopier-Tempolimit';
$string['pace_desc'] = 'Wer mehr Seiten pro Minute abruft, als ein Mensch liest, bekommt „429 Too many requests“, bis die Minute vorbei ist. Angemeldete Benutzer, Ihre eigenen Adressen und per DNS geprüfte Suchmaschinen (Google, Bing, Apple, Yandex) werden nie begrenzt. AJAX-Aufrufe, Webservices und Dateien zählen nicht.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Adressen und E-Mails, die eine Zeit lang gesperrt sind, durch die automatische Sperre oder durch einen Administrator.';
$string['privacy:metadata:blocks:value'] = 'Die gesperrte IP-Adresse oder E-Mail.';
$string['privacy:metadata:events'] = 'Verdächtige Versuche (gefälschte Registrierungen, Angriffe, Scraping), 90 Tage als Beweis für Missbrauchsmeldungen aufbewahrt. Nicht mit Moodle-Konten verknüpft. Niemals Passwörter.';
$string['privacy:metadata:events:fields'] = 'Benutzername, E-Mail und Herkunftsseite, die mit dem Versuch gesendet wurden.';
$string['privacy:metadata:events:ip'] = 'Die IP-Adresse, von der der Versuch kam.';
$string['privacy:metadata:events:timecreated'] = 'Wann der Versuch stattfand.';
$string['privacy:metadata:events:useragent'] = 'Der Name des Browsers oder Programms, den er gesendet hat.';
$string['proxy'] = 'Besucheradresse';
$string['proxy_desc'] = 'Lassen Sie „Verbindungsadresse“, außer die Website liegt hinter einem Proxy: einen Header kann jeder fälschen.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'Der Header wird ignoriert: Diese Verbindung (<code>{$a}</code>) kommt weder von Cloudflare noch von einem vertrauenswürdigen Proxy. Wenn Ihr Proxy im Internet steht, tragen Sie seine Adressen unter „Vertrauenswürdige Proxys“ ein.';
$string['proxynone'] = 'Verbindungsadresse (empfohlen)';
$string['proxyxff'] = 'Anderer Proxy (X-Forwarded-For)';
$string['pwdbreached'] = 'Passwörter aus Datenlecks ablehnen';
$string['pwdbreached_desc'] = 'Fragt Have I Been Pwned mit k-Anonymität: Nur 5 Zeichen des SHA-1 des Passworts verlassen die Website, nie das Passwort. Antwortet der Dienst nicht innerhalb von 3 Sekunden, wird das Passwort akzeptiert. Moodle wendet es an, solange „Kennwortregeln“ aktiviert ist (Website-Administration > Sicherheit > Sicherheitsregeln).';
$string['pwdbreachedrefused'] = 'Dieses Passwort taucht in bekannten Datenlecks auf, deshalb probieren Angreifer es zuerst. Bitte wähle ein anderes.';
$string['pwdmin'] = 'Mindestlänge des Passworts';
$string['pwdmin_desc'] = '8 bis 64 Zeichen; 0 lässt nur Moodles eigene Regel. Gilt, solange „Kennwortregeln“ aktiviert ist.';
$string['pwdshort'] = 'Das Passwort muss mindestens {$a} Zeichen haben.';
$string['rateip'] = 'Seiten pro Minute, pro Adresse';
$string['ratenet'] = 'Seiten pro Minute, pro Netz';
$string['ratenet_desc'] = 'Ein /24-Netz bei IPv4 oder ein /64 bei IPv6: das, was ein Scraper bekommt, wenn er zwischen benachbarten Adressen wechselt.';
$string['rejected'] = 'Die Registrierung konnte nicht abgeschlossen werden.';
$string['review1'] = '24 Stunden durchlassen';
$string['review30'] = '30 Tage';
$string['review7'] = '7 Tage';
$string['reviewapproved'] = 'Durchlassen';
$string['reviewattacker'] = 'Angreifer: blockiert';
$string['reviewattackerbtn'] = 'Angreifer';
$string['reviewbody'] = 'Ein von der Firewall gestoppter Besucher bittet um Überprüfung. Öffnen Sie die Seite von Draco Insomnis, um ihn durchzulassen oder nicht.';
$string['reviewbutton'] = 'Überprüfung anfordern';
$string['reviewdenied'] = 'Abgelehnt';
$string['reviewdeny'] = 'Ablehnen';
$string['reviewemail'] = 'Deine E-Mail';
$string['reviewmessage'] = 'Was hast du gerade gemacht?';
$string['reviewreason'] = 'Überprüfung: {$a}';
$string['reviews'] = 'Überprüfungsanfragen';
$string['reviewsenttext'] = 'Danke. Der Betreiber der Website sieht es sich an und lässt dich durch, falls es ein Fehler war.';
$string['reviewsenttitle'] = 'Anfrage gesendet';
$string['reviewshelp'] = 'Wer von der Firewall gestoppt wurde, kann auf der Sperrseite darum bitten. Lass ihn eine Zeit lang durch, wenn es ein Fehler war. Draco schreibt ihm nie: antworte aus deinem eigenen Postfach, wenn du willst.';
$string['reviewsubject'] = '[{$a}] Jemand bittet Sie, eine Sperre der Firewall zu überprüfen';
$string['shield'] = 'Selbstregistrierung schützen';
$string['shield_desc'] = 'Fügt dem Registrierungsformular eine unsichtbare Falle und einen signierten Seitenstempel hinzu (Selbstregistrierung per E-Mail). Bots bekommen kein Konto; drei Bot-Versuche an einem Tag sperren die Adresse für eine Woche.';
$string['summary'] = 'Firewall: letzte 7 Tage';
$string['summaryips'] = 'Aktivste Adressen:';
$string['summaryline'] = '{$a->total} Angriffe gesehen, {$a->blocked} blockiert.';
$string['summarywhat'] = 'Was:';
$string['taskcleanup'] = 'Draco Insomnis: alte Beweise und abgelaufene Sperren entfernen';
$string['test'] = 'Firewall testen';
$string['testblocked'] = 'Funktioniert: eine Datenbank-Injektion wurde erkannt und blockiert (403).';
$string['testhelp'] = 'Schickt der Website eine harmlose Anfrage in Form eines Angriffs und sagt dir, was passiert ist. Sie wird nicht protokolliert.';
$string['testlogged'] = 'Funktioniert: eine Datenbank-Injektion wurde erkannt. Bei „Nur protokollieren“ wird sie notiert, aber nicht gestoppt; wechsle zu „Blockieren“, wenn du so weit bist.';
$string['testnone'] = 'Der Testangriff wurde nicht erkannt. Bitte melde das an Draco Insomnis.';
$string['testoff'] = 'Die Firewall ist aus: schalte sie ein, speichere und teste erneut.';
$string['testunreachable'] = 'Der Test konnte die Website vom Server selbst aus nicht erreichen (manche Hoster erlauben das nicht). Die Firewall kann trotzdem arbeiten: Sehen Sie sich die letzten Versuche an.';
$string['testupstream'] = 'Der Test wurde vor Moodle gestoppt, von der Firewall des Hosters. Gut: zwei Schichten.';
$string['trusted'] = 'Vertrauenswürdige Proxys';
$string['trusted_desc'] = 'Nur Verbindungen von diesen Adressen dürfen die Besucheradresse per Header setzen. Eine Adresse oder ein Bereich pro Zeile. Leer: dieser Server und private Netze. Die Bereiche von Cloudflare sind schon bekannt.';
$string['unblock'] = 'Entsperren';
$string['unblocked'] = 'Adresse entsperrt.';
$string['waf'] = 'Firewall';
$string['waf_desc'] = 'Stoppt Anfragen in Form eines Angriffs (Datenbank-Injektion, Lesen von Serverdateien, Ausführen von Code, Skripte in Links) und Scanner wie sqlmap oder Nikto. Beginnen Sie mit „Nur protokollieren“ und wechseln Sie nach ein paar Tagen zu „Blockieren“. Fünf Angriffe in 10 Minuten sperren die Adresse für eine Woche; gesperrte Adressen können die Website weiter lesen, aber nichts absenden und sich nicht anmelden. Website-Administratoren und Benutzer mit „Die Firewall von Draco Insomnis umgehen“ werden nie geprüft. Notausgang: define(\'DRACO_WAF_OFF\', true); in config.php.';
$string['wafblock'] = 'Firewall: {$a} Angriffe in 10 Minuten';
$string['yourip'] = 'Ihre Adresse, wie das Plugin sie sieht: <code>{$a->ip}</code> (Verbindungsadresse: <code>{$a->remote}</code>). Wenn die Website hinter Cloudflare oder einem anderen Proxy liegt und diese von Ihrer echten Adresse abweichen, wählen Sie die passende Option unter „Besucheradresse“.';
