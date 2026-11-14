<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'pl' (generated from i18n/pl.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Automatycznie: {$a} prób bota w 24 h';
$string['block'] = 'Zablokuj';
$string['blockadd'] = 'Zablokuj adres lub zakres';
$string['blockadd_desc'] = 'Nigdy administrator ani Twój własny adres. Zakresy nie szersze niż /16 (IPv4) lub /32 (IPv6).';
$string['blockdays'] = 'Na';
$string['blockdone'] = 'Zablokowano: {$a}';
$string['blockedtext'] = 'To żądanie zostało zatrzymane ze względów bezpieczeństwa. Jeśli uważasz, że to pomyłka, skontaktuj się z właścicielem witryny.';
$string['blockedtitle'] = 'Żądanie zablokowane';
$string['blockrefused'] = 'Nic nie zostało zablokowane: wartość jest nieprawidłowa, należy do administratora albo to twój własny adres.';
$string['blocks'] = 'Zablokowane adresy';
$string['blockvalue'] = 'IP lub zakres (np. 203.0.113.0/24)';
$string['coldata'] = 'Dane';
$string['coldate'] = 'Data (UTC)';
$string['colemail'] = 'E-mail';
$string['colip'] = 'Adres';
$string['colmessage'] = 'Wiadomość';
$string['colreason'] = 'Powód';
$string['colsigns'] = 'Oznaki';
$string['coluntil'] = 'Do (UTC)';
$string['colvalue'] = 'Adres lub e-mail';
$string['colverdict'] = 'Werdykt';
$string['colwhere'] = 'Gdzie';
$string['days15'] = '15 dni';
$string['days30'] = '30 dni';
$string['days7'] = '7 dni';
$string['days90'] = '90 dni';
$string['done'] = 'Gotowe.';
$string['dracoinsomnis:bypassfirewall'] = 'Omijanie zapory Draco Insomnis';
$string['events'] = 'Ostatnie podejrzane próby';
$string['events_help'] = 'Przechowywane 90 dni. Nigdy hasła. Plik CSV adresu zawiera wszystko, co zrobił, gotowe do dołączenia do zgłoszenia nadużycia u jego dostawcy sieci.';
$string['evidence'] = 'Draco Insomnis: blokady i dowody';
$string['forever'] = 'Na zawsze';
$string['geo'] = 'Kraje';
$string['geo_desc'] = 'Twoi odwiedzający mogą pochodzić z wielu krajów, a atakujący zmienia kraj przez VPN. Filtruj tylko logowanie, rejestrację i formularze, i zacznij od „Tylko zapisuj”. Administratorzy witryny, osoby, które przepuszczasz, i wyszukiwarki nigdy nie są filtrowani. Wymaga włączonej zapory (zapis lub blokada).';
$string['geoaction'] = 'Co robić';
$string['geocountries'] = 'Kraje (dwuliterowe kody, np. ES, FR, DE)';
$string['geocredit'] = 'Geolokalizacja IP od DB-IP (db-ip.com, CC BY 4.0), pobierana po włączeniu filtra i sprawdzana na Twoim własnym serwerze: żaden adres nie jest nigdzie wysyłany.';
$string['geomode'] = 'Filtr';
$string['geoonly'] = 'Tylko kraje z listy';
$string['georefuse'] = 'Odrzucaj kraje z listy';
$string['geoscope'] = 'Gdzie';
$string['geosensitive'] = 'Logowanie, rejestracja i formularze (zalecane)';
$string['geosite'] = 'Cała witryna';
$string['headers'] = 'Nagłówki bezpieczeństwa';
$string['headers_desc'] = 'Na stronach: bez zgadywania typów plików, bez osadzania w obcych witrynach, mniej danych o pochodzeniu, bez kamery, mikrofonu i lokalizacji dla osadzonych treści. Nigdy nagłówek, który Moodle już wysyła.';
$string['hsts'] = 'Wymuszaj HTTPS przez 6 miesięcy (HSTS)';
$string['hsts_desc'] = 'Tylko jeśli cała witryna działa na HTTPS i tak zostanie: przeglądarki to pamiętają i odrzucają HTTP aż do wygaśnięcia.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Zatrzymuje fałszywe rejestracje bez captchy: boty nie dostają konta, a każda podejrzana próba jest przechowywana 90 dni jako dowód do zgłoszenia nadużycia. Atakującemu nigdy nic nie jest odsyłane.</p><p>Zablokowane adresy i ostatnie próby: <a href="{$a}">Draco Insomnis: blokady i dowody</a>.</p>';
$string['modeblock'] = 'Zablokuj';
$string['modelog'] = 'Tylko zapisuj: notuj, co zostałoby zatrzymane';
$string['modeoff'] = 'Wyłączone';
$string['nets'] = 'Sieci wynajmowanych serwerów';
$string['nets_desc'] = 'Jeden zakres w wierszu (CIDR), dodawany do tych, które wtyczka już zna. Obecność na tej liście tylko dodaje punkty: sama w sobie nigdy nie robi z nikogo bota.';
$string['noblocks'] = 'Obecnie nic nie jest zablokowane.';
$string['noevents'] = 'Na razie nic.';
$string['noreviews'] = 'Brak próśb.';
$string['notdone'] = 'Dla tego adresu nie udało się tego zrobić.';
$string['pace'] = 'Limit tempa przeciw kopiowaniu';
$string['pace_desc'] = 'Kto pobiera więcej stron na minutę, niż czyta człowiek, dostaje „429 Too many requests” do końca minuty. Zalogowani użytkownicy, Twoje własne adresy i wyszukiwarki zweryfikowane przez DNS (Google, Bing, Apple, Yandex) nigdy nie są ograniczani. Wywołania AJAX, usługi sieciowe i pliki się nie liczą.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Adresy i e-maile zablokowane na pewien czas przez automatyczną blokadę lub przez administratora.';
$string['privacy:metadata:blocks:value'] = 'Zablokowany adres IP lub e-mail.';
$string['privacy:metadata:events'] = 'Podejrzane próby (fałszywe rejestracje, ataki, masowe kopiowanie), przechowywane 90 dni jako dowody do zgłoszeń nadużyć. Niepowiązane z kontami Moodle. Nigdy hasła.';
$string['privacy:metadata:events:fields'] = 'Nazwa użytkownika, e-mail i strona odsyłająca wysłane z próbą.';
$string['privacy:metadata:events:ip'] = 'Adres IP, z którego przyszła próba.';
$string['privacy:metadata:events:timecreated'] = 'Kiedy nastąpiła próba.';
$string['privacy:metadata:events:useragent'] = 'Nazwa przeglądarki lub programu, którą wysłała.';
$string['proxy'] = 'Adres odwiedzającego';
$string['proxy_desc'] = 'Zostaw „Adres połączenia”, chyba że witryna stoi za proxy: nagłówek może podrobić każdy.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'Nagłówek jest ignorowany: to połączenie (<code>{$a}</code>) nie pochodzi z Cloudflare ani z zaufanego proxy. Jeśli Twoje proxy jest w internecie, dodaj jego adresy w „Zaufane serwery proxy”.';
$string['proxynone'] = 'Adres połączenia (zalecane)';
$string['proxyxff'] = 'Inne proxy (X-Forwarded-For)';
$string['pwdbreached'] = 'Odrzucaj hasła znalezione w wyciekach danych';
$string['pwdbreached_desc'] = 'Pyta Have I Been Pwned z k-anonimowością: witrynę opuszcza tylko 5 znaków SHA-1 hasła, nigdy samo hasło. Jeśli usługa nie odpowie w 3 sekundy, hasło jest akceptowane. Moodle stosuje to, dopóki „Zasady haseł” są włączone (Administracja witryny > Bezpieczeństwo > Zasady bezpieczeństwa witryny).';
$string['pwdbreachedrefused'] = 'To hasło występuje w znanych wyciekach danych, więc atakujący próbują go najpierw. Wybierz, proszę, inne.';
$string['pwdmin'] = 'Minimalna długość hasła';
$string['pwdmin_desc'] = 'Od 8 do 64 znaków; 0 zostawia tylko własną regułę Moodle. Stosowane, dopóki „Zasady haseł” są włączone.';
$string['pwdshort'] = 'Hasło musi mieć co najmniej {$a} znaków.';
$string['rateip'] = 'Stron na minutę, na adres';
$string['ratenet'] = 'Stron na minutę, na sieć';
$string['ratenet_desc'] = 'Sieć /24 dla IPv4 lub /64 dla IPv6: tyle dostaje scraper, który przeskakuje między sąsiednimi adresami.';
$string['rejected'] = 'Nie udało się ukończyć rejestracji.';
$string['review1'] = 'Przepuść na 24 godziny';
$string['review30'] = '30 dni';
$string['review7'] = '7 dni';
$string['reviewapproved'] = 'Przepuść';
$string['reviewattacker'] = 'Atakujący: zablokowany';
$string['reviewattackerbtn'] = 'Atakujący';
$string['reviewbody'] = 'Odwiedzający zatrzymany przez zaporę prosi o sprawdzenie. Otwórz stronę Draco Insomnis, aby go przepuścić lub nie.';
$string['reviewbutton'] = 'Poproś o sprawdzenie';
$string['reviewdenied'] = 'Odrzucona';
$string['reviewdeny'] = 'Odrzuć';
$string['reviewemail'] = 'Twój e-mail';
$string['reviewmessage'] = 'Co robiłeś?';
$string['reviewreason'] = 'Sprawdzenie: {$a}';
$string['reviews'] = 'Prośby o sprawdzenie';
$string['reviewsenttext'] = 'Dziękujemy. Właściciel witryny to sprawdzi i, jeśli to był błąd, przepuści cię.';
$string['reviewsenttitle'] = 'Prośba wysłana';
$string['reviewshelp'] = 'Osoby zatrzymane przez zaporę mogą poprosić o to ze strony blokady. Przepuść je na jakiś czas, jeśli to był błąd. Draco nigdy do nich nie pisze: odpowiedz ze swojej poczty, jeśli chcesz.';
$string['reviewsubject'] = '[{$a}] Ktoś prosi Cię o sprawdzenie blokady zapory';
$string['shield'] = 'Chroń samodzielną rejestrację';
$string['shield_desc'] = 'Dodaje do formularza rejestracji niewidoczną pułapkę i podpisany znacznik strony (samodzielna rejestracja przez e-mail). Boty nie dostają konta; trzy próby bota w ciągu dnia blokują adres na tydzień.';
$string['summary'] = 'Zapora: ostatnie 7 dni';
$string['summaryips'] = 'Najaktywniejsze adresy:';
$string['summaryline'] = 'Wykryte ataki: {$a->total}, zablokowane: {$a->blocked}.';
$string['summarywhat'] = 'Co:';
$string['taskcleanup'] = 'Draco Insomnis: usuń stare dowody i zakończone blokady';
$string['test'] = 'Przetestuj zaporę';
$string['testblocked'] = 'Działa: wstrzyknięcie do bazy danych zostało rozpoznane i zablokowane (403).';
$string['testhelp'] = 'Wysyła do witryny nieszkodliwe żądanie w kształcie ataku i mówi, co się stało. Nie jest zapisywane.';
$string['testlogged'] = 'Działa: wstrzyknięcie do bazy danych zostało rozpoznane. W trybie „Tylko zapisuj” jest notowane, ale nie zatrzymywane; przełącz na „Blokuj”, gdy będziesz gotowy.';
$string['testnone'] = 'Testowy atak nie został rozpoznany. Zgłoś to, proszę, do Draco Insomnis.';
$string['testoff'] = 'Zapora jest wyłączona: włącz ją, zapisz i przetestuj ponownie.';
$string['testunreachable'] = 'Test nie mógł dotrzeć do witryny z samego serwera (niektóre hostingi na to nie pozwalają). Zapora może mimo to działać: sprawdź ostatnie próby.';
$string['testupstream'] = 'Test został zatrzymany przed Moodle przez zaporę hostingu. Dobrze: dwie warstwy.';
$string['trusted'] = 'Zaufane serwery proxy';
$string['trusted_desc'] = 'Tylko połączenia z tych adresów mogą ustawiać adres odwiedzającego przez nagłówek. Jeden adres lub zakres w wierszu. Puste: ten serwer i sieci prywatne. Zakresy samego Cloudflare są już znane.';
$string['unblock'] = 'Odblokuj';
$string['unblocked'] = 'Adres odblokowany.';
$string['waf'] = 'Zapora';
$string['waf_desc'] = 'Zatrzymuje żądania wyglądające na atak (wstrzyknięcie do bazy danych, odczyt plików serwera, uruchamianie kodu, skrypty w linkach) oraz skanery takie jak sqlmap czy Nikto. Zacznij od „Tylko zapisuj”, a po kilku dniach przejdź na „Zablokuj”. Pięć ataków w 10 minut blokuje adres na tydzień; zablokowane adresy nadal mogą czytać witrynę, ale nie mogą niczego wysyłać ani się logować. Administratorzy witryny i użytkownicy z uprawnieniem „Omijanie zapory Draco Insomnis” nigdy nie są sprawdzani. Wyjście awaryjne: define(\'DRACO_WAF_OFF\', true); w config.php.';
$string['wafblock'] = 'Zapora: {$a} ataków w 10 minut';
$string['yourip'] = 'Twój adres tak, jak widzi go wtyczka: <code>{$a->ip}</code> (adres połączenia: <code>{$a->remote}</code>). Jeśli witryna stoi za Cloudflare lub innym proxy i różnią się one od Twojego prawdziwego adresu, wybierz odpowiednią opcję w „Adres odwiedzającego”.';
