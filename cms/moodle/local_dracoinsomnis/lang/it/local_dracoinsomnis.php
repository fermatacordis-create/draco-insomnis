<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'it' (generated from i18n/it.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Automatico: {$a} tentativi di bot in 24 h';
$string['block'] = 'Blocca';
$string['blockadd'] = 'Blocca un indirizzo o un intervallo';
$string['blockadd_desc'] = 'Mai un amministratore, né il tuo indirizzo. Intervalli non più ampi di /16 (IPv4) o /32 (IPv6).';
$string['blockdays'] = 'Per';
$string['blockdone'] = 'Bloccato: {$a}';
$string['blockedtext'] = 'Questa richiesta è stata fermata per motivi di sicurezza. Se pensi che sia un errore, contatta il proprietario del sito.';
$string['blockedtitle'] = 'Richiesta bloccata';
$string['blockrefused'] = 'Non è stato bloccato nulla: il valore non è valido, appartiene a un amministratore o è il tuo indirizzo.';
$string['blocks'] = 'Indirizzi bloccati';
$string['blockvalue'] = 'IP o intervallo (es. 203.0.113.0/24)';
$string['coldata'] = 'Dati';
$string['coldate'] = 'Data (UTC)';
$string['colemail'] = 'Email';
$string['colip'] = 'Indirizzo';
$string['colmessage'] = 'Messaggio';
$string['colreason'] = 'Motivo';
$string['colsigns'] = 'Segnali';
$string['coluntil'] = 'Fino a (UTC)';
$string['colvalue'] = 'Indirizzo o e-mail';
$string['colverdict'] = 'Verdetto';
$string['colwhere'] = 'Dove';
$string['days15'] = '15 giorni';
$string['days30'] = '30 giorni';
$string['days7'] = '7 giorni';
$string['days90'] = '90 giorni';
$string['done'] = 'Fatto.';
$string['dracoinsomnis:bypassfirewall'] = 'Aggira il firewall di Draco Insomnis';
$string['events'] = 'Ultimi tentativi sospetti';
$string['events_help'] = 'Conservati 90 giorni. Mai password. Il CSV di un indirizzo contiene tutto ciò che ha fatto, pronto da allegare a una segnalazione di abuso al suo fornitore di rete.';
$string['evidence'] = 'Draco Insomnis: blocchi e prove';
$string['forever'] = 'Per sempre';
$string['geo'] = 'Paesi';
$string['geo_desc'] = 'I tuoi visitatori possono arrivare da molti paesi, e un attaccante cambia paese con una VPN. Filtra solo accesso, registrazione e moduli, e inizia con «Solo registro». Amministratori del sito, persone che lasci passare e motori di ricerca non vengono mai filtrati. Serve il firewall attivo (registro o blocco).';
$string['geoaction'] = 'Cosa fare';
$string['geocountries'] = 'Paesi (codici di due lettere, es. ES, FR, DE)';
$string['geocredit'] = 'Geolocalizzazione IP di DB-IP (db-ip.com, CC BY 4.0), scaricata quando attivi il filtro e consultata sul tuo server: nessun indirizzo viene inviato altrove.';
$string['geomode'] = 'Filtro';
$string['geoonly'] = 'Solo i paesi elencati';
$string['georefuse'] = 'Rifiuta i paesi elencati';
$string['geoscope'] = 'Dove';
$string['geosensitive'] = 'Accesso, registrazione e moduli (consigliato)';
$string['geosite'] = 'Tutto il sito';
$string['headers'] = 'Intestazioni di sicurezza';
$string['headers_desc'] = 'Nelle pagine: niente indovinare i tipi di file, niente incorporamento in altri siti, meno dati di provenienza, niente fotocamera, microfono o posizione per i contenuti incorporati. Mai una che Moodle invia già.';
$string['hsts'] = 'Forza HTTPS per 6 mesi (HSTS)';
$string['hsts_desc'] = 'Solo se tutto il sito funziona in HTTPS e continuerà così: i browser lo ricordano e rifiutano HTTP fino alla scadenza.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Ferma le registrazioni false senza captcha: i bot non ottengono un account e ogni tentativo sospetto viene conservato 90 giorni come prova per una segnalazione di abuso. All’attaccante non viene mai rimandato nulla.</p><p>Indirizzi bloccati e ultimi tentativi: <a href="{$a}">Draco Insomnis: blocchi e prove</a>.</p>';
$string['modeblock'] = 'Blocca';
$string['modelog'] = 'Solo registro: annota ciò che fermerebbe';
$string['modeoff'] = 'Disattivato';
$string['nets'] = 'Reti di server in affitto';
$string['nets_desc'] = 'Un intervallo per riga (CIDR), aggiunto a quelli che il plugin già conosce. Essere in questa lista aggiunge solo punti: da sola non rende mai nessuno un bot.';
$string['noblocks'] = 'Al momento non c’è nulla di bloccato.';
$string['noevents'] = 'Ancora niente.';
$string['noreviews'] = 'Nessuna richiesta.';
$string['notdone'] = 'Non è stato possibile per quell’indirizzo.';
$string['pace'] = 'Limite di ritmo anti-copia';
$string['pace_desc'] = 'Chi chiede più pagine al minuto di quante ne legga una persona riceve «429 Too many requests» fino alla fine del minuto. Gli utenti connessi, i tuoi indirizzi e i motori di ricerca verificati via DNS (Google, Bing, Apple, Yandex) non vengono mai limitati. Chiamate AJAX, servizi web e file non contano.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Indirizzi ed e-mail bloccati per un periodo, dal blocco automatico o da un amministratore.';
$string['privacy:metadata:blocks:value'] = 'L’indirizzo IP o l’e-mail bloccata.';
$string['privacy:metadata:events'] = 'Tentativi sospetti (registrazioni false, attacchi, copia massiva), conservati 90 giorni come prove per segnalazioni di abuso. Non collegati agli account Moodle. Mai password.';
$string['privacy:metadata:events:fields'] = 'Nome utente, e-mail e pagina di provenienza inviati con il tentativo.';
$string['privacy:metadata:events:ip'] = 'L’indirizzo IP da cui è arrivato il tentativo.';
$string['privacy:metadata:events:timecreated'] = 'Quando è avvenuto il tentativo.';
$string['privacy:metadata:events:useragent'] = 'Il nome del browser o del programma che ha inviato.';
$string['proxy'] = 'Indirizzo del visitatore';
$string['proxy_desc'] = 'Lascia «Indirizzo della connessione» a meno che il sito non sia dietro un proxy: chiunque può falsificare un’intestazione.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'L’intestazione viene ignorata: questa connessione (<code>{$a}</code>) non arriva da Cloudflare né da un proxy fidato. Se il tuo proxy è su internet, aggiungi i suoi indirizzi in «Proxy fidati».';
$string['proxynone'] = 'Indirizzo della connessione (consigliato)';
$string['proxyxff'] = 'Altro proxy (X-Forwarded-For)';
$string['pwdbreached'] = 'Rifiuta le password trovate in fughe di dati';
$string['pwdbreached_desc'] = 'Chiede a Have I Been Pwned con k-anonimato: dal sito escono solo 5 caratteri dello SHA-1 della password, mai la password. Se il servizio non risponde entro 3 secondi, la password viene accettata. Moodle la applica finché «Criteri password» è attivo (Amministrazione del sito > Sicurezza > Criteri di sicurezza del sito).';
$string['pwdbreachedrefused'] = 'Questa password compare in fughe di dati note, quindi gli attaccanti la provano per prima. Scegline un’altra, per favore.';
$string['pwdmin'] = 'Lunghezza minima della password';
$string['pwdmin_desc'] = 'Da 8 a 64 caratteri; 0 lascia solo la regola di Moodle. Si applica finché «Criteri password» è attivo.';
$string['pwdshort'] = 'La password deve avere almeno {$a} caratteri.';
$string['rateip'] = 'Pagine al minuto, per indirizzo';
$string['ratenet'] = 'Pagine al minuto, per rete';
$string['ratenet_desc'] = 'Una rete /24 in IPv4 o /64 in IPv6: ciò che ottiene uno scraper che ruota tra indirizzi vicini.';
$string['rejected'] = 'Non è stato possibile completare la registrazione.';
$string['review1'] = 'Lascia passare 24 ore';
$string['review30'] = '30 giorni';
$string['review7'] = '7 giorni';
$string['reviewapproved'] = 'Lascia passare';
$string['reviewattacker'] = 'Attaccante: bloccato';
$string['reviewattackerbtn'] = 'Attaccante';
$string['reviewbody'] = 'Un visitatore fermato dal firewall chiede una revisione. Apri la pagina di Draco Insomnis per lasciarlo passare o no.';
$string['reviewbutton'] = 'Chiedi una revisione';
$string['reviewdenied'] = 'Negata';
$string['reviewdeny'] = 'Nega';
$string['reviewemail'] = 'La tua e-mail';
$string['reviewmessage'] = 'Cosa stavi facendo?';
$string['reviewreason'] = 'Revisione: {$a}';
$string['reviews'] = 'Richieste di revisione';
$string['reviewsenttext'] = 'Grazie. Il responsabile del sito la esaminerà e, se è stato un errore, ti lascerà passare.';
$string['reviewsenttitle'] = 'Richiesta inviata';
$string['reviewshelp'] = 'Chi è stato fermato dal firewall può chiederlo dalla pagina di blocco. Lascialo passare per un po’ se era un errore. Draco non gli scrive mai: rispondi dalla tua e-mail se vuoi.';
$string['reviewsubject'] = '[{$a}] Qualcuno ti chiede di rivedere un blocco del firewall';
$string['shield'] = 'Proteggi l’autoregistrazione';
$string['shield_desc'] = 'Aggiunge una trappola invisibile e un timbro firmato della pagina al modulo di registrazione (autoregistrazione via e-mail). I bot non ottengono un account; tre tentativi di bot in un giorno bloccano l’indirizzo per una settimana.';
$string['summary'] = 'Firewall: ultimi 7 giorni';
$string['summaryips'] = 'Indirizzi più attivi:';
$string['summaryline'] = '{$a->total} attacchi visti, {$a->blocked} bloccati.';
$string['summarywhat'] = 'Cosa:';
$string['taskcleanup'] = 'Draco Insomnis: elimina le prove vecchie e i blocchi scaduti';
$string['test'] = 'Prova il firewall';
$string['testblocked'] = 'Funziona: un’iniezione nel database è stata riconosciuta e bloccata (403).';
$string['testhelp'] = 'Invia al sito una richiesta innocua a forma di attacco e ti dice cosa è successo. Non viene registrata.';
$string['testlogged'] = 'Funziona: un’iniezione nel database è stata riconosciuta. In «Solo registro» viene annotata ma non fermata; passa a «Blocca» quando sei pronto.';
$string['testnone'] = 'L’attacco di prova non è stato riconosciuto. Segnalalo a Draco Insomnis, per favore.';
$string['testoff'] = 'Il firewall è spento: accendilo, salva e prova di nuovo.';
$string['testunreachable'] = 'Il test non ha potuto raggiungere il sito dal server stesso (alcuni hosting non lo permettono). Il firewall può comunque funzionare: guarda gli ultimi tentativi.';
$string['testupstream'] = 'Il test è stato fermato prima di arrivare a Moodle, dal firewall dell’hosting. Bene: due livelli.';
$string['trusted'] = 'Proxy fidati';
$string['trusted_desc'] = 'Solo le connessioni da questi indirizzi possono impostare l’indirizzo del visitatore tramite un’intestazione. Un indirizzo o intervallo per riga. Vuoto: questo server e le reti private. Gli intervalli di Cloudflare sono già noti.';
$string['unblock'] = 'Sblocca';
$string['unblocked'] = 'Indirizzo sbloccato.';
$string['waf'] = 'Firewall';
$string['waf_desc'] = 'Ferma le richieste con la forma di un attacco (iniezione nel database, lettura di file del server, esecuzione di codice, script nei link) e gli scanner come sqlmap o Nikto. Inizia con «Solo registro» e passa a «Blocca» dopo qualche giorno. Cinque attacchi in 10 minuti bloccano l’indirizzo per una settimana; gli indirizzi bloccati possono ancora leggere il sito, ma non inviare né accedere. Gli amministratori del sito e gli utenti con «Aggira il firewall di Draco Insomnis» non vengono mai ispezionati. Uscita di emergenza: define(\'DRACO_WAF_OFF\', true); in config.php.';
$string['wafblock'] = 'Firewall: {$a} attacchi in 10 minuti';
$string['yourip'] = 'Il tuo indirizzo come lo vede il plugin: <code>{$a->ip}</code> (indirizzo della connessione: <code>{$a->remote}</code>). Se il sito è dietro Cloudflare o un altro proxy e non corrispondono al tuo indirizzo reale, scegli l’opzione adatta in «Indirizzo del visitatore».';
