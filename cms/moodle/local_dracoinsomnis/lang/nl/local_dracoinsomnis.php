<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'nl' (generated from i18n/nl.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Automatisch: {$a} botpogingen in 24 u';
$string['block'] = 'Blokkeren';
$string['blockadd'] = 'Een adres of bereik blokkeren';
$string['blockadd_desc'] = 'Nooit een beheerder, en nooit uw eigen adres. Bereiken niet breder dan /16 (IPv4) of /32 (IPv6).';
$string['blockdays'] = 'Voor';
$string['blockdone'] = 'Geblokkeerd: {$a}';
$string['blockedtext'] = 'Dit verzoek is om veiligheidsredenen tegengehouden. Denk je dat dit een vergissing is, neem dan contact op met de eigenaar van de site.';
$string['blockedtitle'] = 'Verzoek geblokkeerd';
$string['blockrefused'] = 'Er is niets geblokkeerd: de waarde is ongeldig, hoort bij een beheerder of is je eigen adres.';
$string['blocks'] = 'Geblokkeerde adressen';
$string['blockvalue'] = 'IP of bereik (bijv. 203.0.113.0/24)';
$string['coldata'] = 'Gegevens';
$string['coldate'] = 'Datum (UTC)';
$string['colemail'] = 'E-mail';
$string['colip'] = 'Adres';
$string['colmessage'] = 'Bericht';
$string['colreason'] = 'Reden';
$string['colsigns'] = 'Signalen';
$string['coluntil'] = 'Tot (UTC)';
$string['colvalue'] = 'Adres of e-mail';
$string['colverdict'] = 'Oordeel';
$string['colwhere'] = 'Waar';
$string['days15'] = '15 dagen';
$string['days30'] = '30 dagen';
$string['days7'] = '7 dagen';
$string['days90'] = '90 dagen';
$string['done'] = 'Klaar.';
$string['dracoinsomnis:bypassfirewall'] = 'De firewall van Draco Insomnis omzeilen';
$string['events'] = 'Laatste verdachte pogingen';
$string['events_help'] = '90 dagen bewaard. Nooit wachtwoorden. De CSV van een adres bevat alles wat het deed, klaar om bij een misbruikmelding aan de netwerkprovider te voegen.';
$string['evidence'] = 'Draco Insomnis: blokkades en bewijs';
$string['forever'] = 'Voor altijd';
$string['geo'] = 'Landen';
$string['geo_desc'] = 'Uw bezoekers kunnen uit veel landen komen, en een aanvaller wisselt van land met een VPN. Filter alleen inloggen, registreren en formulieren, en begin met ‘Alleen loggen’. Sitebeheerders, mensen die u doorlaat en zoekmachines worden nooit gefilterd. De firewall moet aan staan (loggen of blokkeren).';
$string['geoaction'] = 'Wat te doen';
$string['geocountries'] = 'Landen (tweeletterige codes, bijv. ES, FR, DE)';
$string['geocredit'] = 'IP-geolocatie door DB-IP (db-ip.com, CC BY 4.0), gedownload wanneer u het filter aanzet en opgezocht op uw eigen server: er wordt nergens een adres naartoe gestuurd.';
$string['geomode'] = 'Filter';
$string['geoonly'] = 'Alleen de genoemde landen';
$string['georefuse'] = 'Weiger de genoemde landen';
$string['geoscope'] = 'Waar';
$string['geosensitive'] = 'Inloggen, aanmelden en formulieren (aanbevolen)';
$string['geosite'] = 'De hele site';
$string['headers'] = 'Beveiligingsheaders';
$string['headers_desc'] = 'Op pagina’s: geen raden van bestandstypen, niet insluiten in andere sites, minder herkomstgegevens, geen camera, microfoon of locatie voor ingesloten inhoud. Nooit een header die Moodle al verzendt.';
$string['hsts'] = 'HTTPS 6 maanden afdwingen (HSTS)';
$string['hsts_desc'] = 'Alleen als de hele site via HTTPS werkt en dat zo blijft: browsers onthouden het en weigeren HTTP tot het verloopt.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Stopt nepregistraties zonder captcha’s: bots krijgen geen account en elke verdachte poging wordt 90 dagen bewaard als bewijs voor een misbruikmelding. Er wordt nooit iets teruggestuurd naar de aanvaller.</p><p>Geblokkeerde adressen en laatste pogingen: <a href="{$a}">Draco Insomnis: blokkades en bewijs</a>.</p>';
$string['modeblock'] = 'Blokkeren';
$string['modelog'] = 'Alleen loggen: noteren wat het zou stoppen';
$string['modeoff'] = 'Uit';
$string['nets'] = 'Netwerken van gehuurde servers';
$string['nets_desc'] = 'Eén bereik per regel (CIDR), naast de bereiken die de plugin al kent. Op deze lijst staan geeft alleen punten: op zichzelf maakt het niemand tot bot.';
$string['noblocks'] = 'Er is nu niets geblokkeerd.';
$string['noevents'] = 'Nog niets.';
$string['noreviews'] = 'Geen verzoeken.';
$string['notdone'] = 'Dat kon niet voor dat adres.';
$string['pace'] = 'Tempolimiet tegen kopiëren';
$string['pace_desc'] = 'Wie meer pagina’s per minuut opvraagt dan een mens leest, krijgt ‘429 Too many requests’ tot de minuut voorbij is. Ingelogde gebruikers, uw eigen adressen en via DNS gecontroleerde zoekmachines (Google, Bing, Apple, Yandex) worden nooit beperkt. AJAX-aanroepen, webservices en bestanden tellen niet mee.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Adressen en e-mails die een tijd geblokkeerd zijn, door de automatische blokkade of door een beheerder.';
$string['privacy:metadata:blocks:value'] = 'Het geblokkeerde IP-adres of e-mailadres.';
$string['privacy:metadata:events'] = 'Verdachte pogingen (nepregistraties, aanvallen, scrapen), 90 dagen bewaard als bewijs voor misbruikmeldingen. Niet gekoppeld aan Moodle-accounts. Nooit wachtwoorden.';
$string['privacy:metadata:events:fields'] = 'Gebruikersnaam, e-mail en verwijzende pagina die met de poging zijn meegestuurd.';
$string['privacy:metadata:events:ip'] = 'Het IP-adres waar de poging vandaan kwam.';
$string['privacy:metadata:events:timecreated'] = 'Wanneer de poging plaatsvond.';
$string['privacy:metadata:events:useragent'] = 'De naam van de browser of het programma die werd meegestuurd.';
$string['proxy'] = 'Adres van de bezoeker';
$string['proxy_desc'] = 'Laat ‘Verbindingsadres’ staan, tenzij de site achter een proxy staat: een header kan door iedereen worden vervalst.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'De header wordt genegeerd: deze verbinding (<code>{$a}</code>) komt niet van Cloudflare of van een vertrouwde proxy. Staat uw proxy op internet, voeg dan zijn adressen toe bij ‘Vertrouwde proxy’s’.';
$string['proxynone'] = 'Verbindingsadres (aanbevolen)';
$string['proxyxff'] = 'Andere proxy (X-Forwarded-For)';
$string['pwdbreached'] = 'Wachtwoorden uit datalekken weigeren';
$string['pwdbreached_desc'] = 'Vraagt Have I Been Pwned met k-anonimiteit: alleen 5 tekens van de SHA-1 van het wachtwoord verlaten de site, nooit het wachtwoord. Antwoordt de dienst niet binnen 3 seconden, dan wordt het wachtwoord geaccepteerd. Moodle past het toe zolang ‘Wachtwoordbeleid’ aan staat (Site-beheer > Beveiliging > Beveiligingsinstellingen site).';
$string['pwdbreachedrefused'] = 'Dit wachtwoord komt voor in bekende datalekken, dus aanvallers proberen het als eerste. Kies alsjeblieft een ander.';
$string['pwdmin'] = 'Minimale wachtwoordlengte';
$string['pwdmin_desc'] = '8 tot 64 tekens; 0 laat alleen de eigen regel van Moodle. Geldt zolang ‘Wachtwoordbeleid’ aan staat.';
$string['pwdshort'] = 'Het wachtwoord moet minstens {$a} tekens hebben.';
$string['rateip'] = 'Pagina’s per minuut, per adres';
$string['ratenet'] = 'Pagina’s per minuut, per netwerk';
$string['ratenet_desc'] = 'Een /24-netwerk voor IPv4 of een /64 voor IPv6: wat een scraper krijgt als hij tussen naburige adressen wisselt.';
$string['rejected'] = 'De registratie kon niet worden afgerond.';
$string['review1'] = '24 uur doorlaten';
$string['review30'] = '30 dagen';
$string['review7'] = '7 dagen';
$string['reviewapproved'] = 'Doorlaten';
$string['reviewattacker'] = 'Aanvaller: geblokkeerd';
$string['reviewattackerbtn'] = 'Aanvaller';
$string['reviewbody'] = 'Een bezoeker die door de firewall is gestopt, vraagt om een controle. Open de pagina van Draco Insomnis om hem wel of niet door te laten.';
$string['reviewbutton'] = 'Om controle vragen';
$string['reviewdenied'] = 'Geweigerd';
$string['reviewdeny'] = 'Weigeren';
$string['reviewemail'] = 'Je e-mail';
$string['reviewmessage'] = 'Wat was je aan het doen?';
$string['reviewreason'] = 'Controle: {$a}';
$string['reviews'] = 'Controleverzoeken';
$string['reviewsenttext'] = 'Bedankt. De beheerder van de site bekijkt het en laat je door als het een vergissing was.';
$string['reviewsenttitle'] = 'Verzoek verzonden';
$string['reviewshelp'] = 'Wie door de firewall is tegengehouden, kan het vragen vanaf de blokkeerpagina. Laat hem een tijdje door als het een vergissing was. Draco schrijft hem nooit: antwoord vanuit je eigen mail als je wilt.';
$string['reviewsubject'] = '[{$a}] Iemand vraagt u een blokkade van de firewall te controleren';
$string['shield'] = 'Zelfregistratie beschermen';
$string['shield_desc'] = 'Voegt een onzichtbare val en een ondertekende paginastempel toe aan het registratieformulier (zelfregistratie via e-mail). Bots krijgen geen account; drie botpogingen op één dag blokkeren het adres een week.';
$string['summary'] = 'Firewall: laatste 7 dagen';
$string['summaryips'] = 'Drukste adressen:';
$string['summaryline'] = '{$a->total} aanvallen gezien, {$a->blocked} geblokkeerd.';
$string['summarywhat'] = 'Wat:';
$string['taskcleanup'] = 'Draco Insomnis: oud bewijs en afgelopen blokkades verwijderen';
$string['test'] = 'Firewall testen';
$string['testblocked'] = 'Werkt: een database-injectie werd herkend en geblokkeerd (403).';
$string['testhelp'] = 'Stuurt de site een onschuldig verzoek in de vorm van een aanval en vertelt je wat er gebeurde. Het wordt niet gelogd.';
$string['testlogged'] = 'Werkt: een database-injectie werd herkend. Bij ‘Alleen loggen’ wordt die genoteerd maar niet tegengehouden; schakel over naar ‘Blokkeren’ als je zover bent.';
$string['testnone'] = 'De testaanval werd niet herkend. Meld dit alsjeblieft aan Draco Insomnis.';
$string['testoff'] = 'De firewall staat uit: zet hem aan, sla op en test opnieuw.';
$string['testunreachable'] = 'De test kon de site niet bereiken vanaf de server zelf (sommige hosts staan dat niet toe). De firewall kan toch werken: bekijk de laatste pogingen.';
$string['testupstream'] = 'De test werd vóór Moodle gestopt door de firewall van de host. Goed: twee lagen.';
$string['trusted'] = 'Vertrouwde proxy’s';
$string['trusted_desc'] = 'Alleen verbindingen van deze adressen mogen het bezoekersadres via een header doorgeven. Eén adres of bereik per regel. Leeg: deze server en privénetwerken. De bereiken van Cloudflare zelf zijn al bekend.';
$string['unblock'] = 'Deblokkeren';
$string['unblocked'] = 'Adres gedeblokkeerd.';
$string['waf'] = 'Firewall';
$string['waf_desc'] = 'Stopt verzoeken die op een aanval lijken (database-injectie, serverbestanden lezen, code uitvoeren, scripts in links) en scanners zoals sqlmap of Nikto. Begin met ‘Alleen loggen’ en ga na een paar dagen naar ‘Blokkeren’. Vijf aanvallen in 10 minuten blokkeren het adres een week; geblokkeerde adressen kunnen de site nog lezen, maar niets versturen of inloggen. Sitebeheerders en gebruikers met ‘De firewall van Draco Insomnis omzeilen’ worden nooit gecontroleerd. Nooduitgang: define(\'DRACO_WAF_OFF\', true); in config.php.';
$string['wafblock'] = 'Firewall: {$a} aanvallen in 10 minuten';
$string['yourip'] = 'Uw adres zoals de plugin het ziet: <code>{$a->ip}</code> (verbindingsadres: <code>{$a->remote}</code>). Als de site achter Cloudflare of een andere proxy staat en deze verschillen van uw echte adres, kies dan de passende optie bij ‘Bezoekersadres’.';
