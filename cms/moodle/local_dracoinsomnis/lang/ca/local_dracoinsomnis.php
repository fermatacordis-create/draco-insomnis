<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'ca' (generated from i18n/ca.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Automàtic: {$a} intents de bot en 24 h';
$string['block'] = 'Bloqueja';
$string['blockadd'] = 'Bloquejar una adreça o un rang';
$string['blockadd_desc'] = 'Mai un administrador ni la teva pròpia adreça. Rangs no més amplis que /16 (IPv4) o /32 (IPv6).';
$string['blockdays'] = 'Durant';
$string['blockdone'] = 'Bloquejat: {$a}';
$string['blockedtext'] = 'Aquesta petició s’ha aturat per seguretat. Si creus que és un error, contacta amb el propietari del web.';
$string['blockedtitle'] = 'Petició bloquejada';
$string['blockrefused'] = 'No s’ha bloquejat res: la dada no és vàlida, és d’un administrador o és la teva pròpia adreça.';
$string['blocks'] = 'Adreces bloquejades';
$string['blockvalue'] = 'IP o rang (p. ex. 203.0.113.0/24)';
$string['coldata'] = 'Dades';
$string['coldate'] = 'Data (UTC)';
$string['colemail'] = 'Correu';
$string['colip'] = 'Adreça';
$string['colmessage'] = 'Missatge';
$string['colreason'] = 'Motiu';
$string['colsigns'] = 'Senyals';
$string['coluntil'] = 'Fins a (UTC)';
$string['colvalue'] = 'Adreça o correu';
$string['colverdict'] = 'Veredicte';
$string['colwhere'] = 'On';
$string['days15'] = '15 dies';
$string['days30'] = '30 dies';
$string['days7'] = '7 dies';
$string['days90'] = '90 dies';
$string['done'] = 'Fet.';
$string['dracoinsomnis:bypassfirewall'] = 'Saltar-se el tallafoc de Draco Insomnis';
$string['events'] = 'Últims intents sospitosos';
$string['events_help'] = 'Es guarden 90 dies. Mai contrasenyes. El CSV d’una adreça conté tot el que ha fet, a punt per adjuntar a una denúncia d’abús al seu proveïdor de xarxa.';
$string['evidence'] = 'Draco Insomnis: bloquejos i proves';
$string['forever'] = 'Per sempre';
$string['geo'] = 'Països';
$string['geo_desc'] = 'Els teus visitants poden venir de molts països, i un atacant canvia de país amb una VPN. Filtra només l’inici de sessió, el registre i els formularis, i comença amb «Només registrar». Els administradors del lloc, les persones que deixes passar i els cercadors no es filtren mai. Cal el tallafoc engegat (registrar o bloquejar).';
$string['geoaction'] = 'Què fer';
$string['geocountries'] = 'Països (codis de dues lletres, p. ex. ES, FR, DE)';
$string['geocredit'] = 'Geolocalització d’IP de DB-IP (db-ip.com, CC BY 4.0), baixada quan actives el filtre i consultada al teu propi servidor: no s’envia cap adreça enlloc.';
$string['geomode'] = 'Filtre';
$string['geoonly'] = 'Només els països de la llista';
$string['georefuse'] = 'Rebutjar els països de la llista';
$string['geoscope'] = 'On';
$string['geosensitive'] = 'Accés, altes i formularis (recomanat)';
$string['geosite'] = 'Tot el lloc';
$string['headers'] = 'Capçaleres de seguretat';
$string['headers_desc'] = 'A les pàgines: sense endevinar tipus de fitxer, sense incrustar-les en altres llocs, menys dades de procedència, sense càmera, micròfon ni ubicació per al contingut incrustat. Mai una que Moodle ja enviï.';
$string['hsts'] = 'Forçar HTTPS durant 6 mesos (HSTS)';
$string['hsts_desc'] = 'Només si tot el lloc funciona amb HTTPS i hi continuarà: els navegadors ho recorden i rebutgen HTTP fins que caduqui.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Atura els registres falsos sense captcha: els bots no obtenen compte i cada intent sospitós es guarda 90 dies com a prova per a una denúncia d’abús. Mai no s’envia res a l’atacant.</p><p>Adreces bloquejades i últims intents: <a href="{$a}">Draco Insomnis: bloquejos i proves</a>.</p>';
$string['modeblock'] = 'Bloqueja';
$string['modelog'] = 'Només registrar el que aturaria';
$string['modeoff'] = 'Desactivat';
$string['nets'] = 'Xarxes de servidors llogats';
$string['nets_desc'] = 'Un rang per línia (CIDR), afegit als que el connector ja coneix. Ser en aquesta llista només suma punts: per si sola, mai no converteix ningú en bot.';
$string['noblocks'] = 'Ara no hi ha res bloquejat.';
$string['noevents'] = 'Encara res.';
$string['noreviews'] = 'No hi ha sol·licituds.';
$string['notdone'] = 'No s’ha pogut fer per a aquesta adreça.';
$string['pace'] = 'Límit de ritme anticòpia';
$string['pace_desc'] = 'Qui demana més pàgines per minut de les que llegeix una persona rep «429 Too many requests» fins que acaba el minut. Els usuaris amb la sessió iniciada, les teves pròpies adreces i els cercadors verificats per DNS (Google, Bing, Apple, Yandex) no es limiten mai. Les crides AJAX, els serveis web i els fitxers no compten.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Adreces i correus bloquejats durant un temps, pel bloqueig automàtic o per un administrador.';
$string['privacy:metadata:blocks:value'] = 'L’adreça IP o el correu bloquejat.';
$string['privacy:metadata:events'] = 'Intents sospitosos (registres falsos, atacs, còpia massiva), guardats 90 dies com a prova per a denúncies d’abús. No estan lligats a comptes de Moodle. Mai contrasenyes.';
$string['privacy:metadata:events:fields'] = 'Nom d’usuari, correu i pàgina de procedència enviats amb l’intent.';
$string['privacy:metadata:events:ip'] = 'L’adreça IP d’on venia l’intent.';
$string['privacy:metadata:events:timecreated'] = 'Quan va passar l’intent.';
$string['privacy:metadata:events:useragent'] = 'El nom del navegador o del programa que va enviar.';
$string['proxy'] = 'IP del visitant';
$string['proxy_desc'] = 'Deixa «Adreça de la connexió» llevat que el lloc sigui darrere d’un proxy: qualsevol pot falsificar una capçalera.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'La capçalera s’ignora: aquesta connexió (<code>{$a}</code>) no ve de Cloudflare ni d’un proxy de confiança. Si el teu proxy és a internet, afegeix-ne les adreces a «Proxies de confiança».';
$string['proxynone'] = 'Adreça de la connexió (recomanat)';
$string['proxyxff'] = 'Un altre proxy (X-Forwarded-For)';
$string['pwdbreached'] = 'Rebutjar contrasenyes trobades en filtracions de dades';
$string['pwdbreached_desc'] = 'Pregunta a Have I Been Pwned amb k-anonimat: del lloc només en surten 5 caràcters de l’SHA-1 de la contrasenya, mai la contrasenya. Si el servei no respon en 3 segons, la contrasenya s’accepta. Moodle ho aplica mentre «Política de contrasenyes» estigui activada (Administració del lloc > Seguretat > Polítiques de seguretat del lloc).';
$string['pwdbreachedrefused'] = 'Aquesta contrasenya apareix en filtracions de dades conegudes, i els atacants la proven primer. Tria\'n una altra, si us plau.';
$string['pwdmin'] = 'Longitud mínima de la contrasenya';
$string['pwdmin_desc'] = 'De 8 a 64 caràcters; amb 0 queda només la regla pròpia de Moodle. S’aplica mentre «Política de contrasenyes» estigui activada.';
$string['pwdshort'] = 'La contrasenya ha de tenir com a mínim {$a} caràcters.';
$string['rateip'] = 'Pàgines per minut, per adreça';
$string['ratenet'] = 'Pàgines per minut, per xarxa';
$string['ratenet_desc'] = 'Una xarxa /24 en IPv4 o /64 en IPv6: el que obté un copiador que va canviant d’adreces veïnes.';
$string['rejected'] = 'No s’ha pogut completar el registre.';
$string['review1'] = 'Deixar passar 24 hores';
$string['review30'] = '30 dies';
$string['review7'] = '7 dies';
$string['reviewapproved'] = 'Deixar passar';
$string['reviewattacker'] = 'Atacant: bloquejat';
$string['reviewattackerbtn'] = 'Atacant';
$string['reviewbody'] = 'Un visitant aturat pel tallafoc demana una revisió. Obre la pàgina de Draco Insomnis per deixar-lo passar o no.';
$string['reviewbutton'] = 'Demanar una revisió';
$string['reviewdenied'] = 'Denegada';
$string['reviewdeny'] = 'Denegar';
$string['reviewemail'] = 'El teu correu';
$string['reviewmessage'] = 'Què estaves fent?';
$string['reviewreason'] = 'Revisió: {$a}';
$string['reviews'] = 'Sol·licituds de revisió';
$string['reviewsenttext'] = 'Gràcies. El responsable del lloc ho revisarà i, si va ser un error, et deixarà passar.';
$string['reviewsenttitle'] = 'Sol·licitud enviada';
$string['reviewshelp'] = 'Qui ha estat aturat pel tallafoc ho pot demanar des de la pàgina de bloqueig. Deixa\'l passar un temps si va ser un error. Draco mai no li escriu: respon-li des del teu correu si vols.';
$string['reviewsubject'] = '[{$a}] Algú et demana que revisis un bloqueig del tallafoc';
$string['shield'] = 'Protegir l’autoregistre';
$string['shield_desc'] = 'Afegeix una trampa invisible i un segell signat de la pàgina al formulari de registre (autoregistre per correu). Els bots no obtenen compte; tres intents de bot en un dia bloquegen l’adreça una setmana.';
$string['summary'] = 'Tallafoc: últims 7 dies';
$string['summaryips'] = 'Adreces més actives:';
$string['summaryline'] = '{$a->total} atacs vistos, {$a->blocked} bloquejats.';
$string['summarywhat'] = 'Què:';
$string['taskcleanup'] = 'Draco Insomnis: treure proves antigues i bloquejos acabats';
$string['test'] = 'Provar el tallafoc';
$string['testblocked'] = 'Funciona: s\'ha reconegut una injecció a la base de dades i s\'ha bloquejat (403).';
$string['testhelp'] = 'Envia al lloc una petició inofensiva amb forma d\'atac i et diu què ha passat. No es registra.';
$string['testlogged'] = 'Funciona: s\'ha reconegut una injecció a la base de dades. En «Només registrar» s\'anota però no s\'atura; passa a «Bloquejar» quan estiguis a punt.';
$string['testnone'] = 'No s\'ha reconegut l\'atac de prova. Avisa Draco Insomnis, si us plau.';
$string['testoff'] = 'El tallafoc està apagat: engega\'l, desa i torna a provar.';
$string['testunreachable'] = 'La prova no ha pogut arribar al lloc des del mateix servidor (alguns allotjaments no ho permeten). El tallafoc pot funcionar igualment: mira els últims intents.';
$string['testupstream'] = 'La prova s’ha aturat abans d’arribar a Moodle, al tallafoc del mateix allotjament. Bé: dues capes.';
$string['trusted'] = 'Proxies de confiança';
$string['trusted_desc'] = 'Només les connexions d’aquestes adreces poden fixar l’adreça del visitant amb una capçalera. Una adreça o rang per línia. Buit: aquest servidor i les xarxes privades. Els rangs de Cloudflare ja són coneguts.';
$string['unblock'] = 'Desbloqueja';
$string['unblocked'] = 'Adreça desbloquejada.';
$string['waf'] = 'Tallafoc';
$string['waf_desc'] = 'Atura les peticions amb forma d’atac (injecció a la base de dades, lectura de fitxers del servidor, execució de codi, scripts als enllaços) i els escàners com sqlmap o Nikto. Comença amb «Només registrar» i passa a «Bloqueja» al cap d’uns dies. Cinc atacs en 10 minuts bloquegen l’adreça una setmana; les adreces bloquejades poden continuar llegint el lloc, però no enviar res ni iniciar sessió. Els administradors del lloc i els usuaris amb «Saltar-se el tallafoc de Draco Insomnis» no s’inspeccionen mai. Sortida d’emergència: define(\'DRACO_WAF_OFF\', true); a config.php.';
$string['wafblock'] = 'Tallafoc: {$a} atacs en 10 minuts';
$string['yourip'] = 'La teva adreça tal com la veu el connector: <code>{$a->ip}</code> (adreça de la connexió: <code>{$a->remote}</code>). Si el lloc és darrere de Cloudflare o d’un altre proxy i no coincideixen amb la teva adreça real, tria l’opció corresponent a «IP del visitant».';
