<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'ko' (generated from i18n/ko.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = '자동: 24시간에 봇 시도 {$a}번';
$string['block'] = '차단';
$string['blockadd'] = '주소 또는 범위 차단';
$string['blockadd_desc'] = '관리자와 내 주소는 차단하지 않습니다. 범위는 /16(IPv4) 또는 /32(IPv6)보다 넓을 수 없습니다.';
$string['blockdays'] = '기간';
$string['blockdone'] = '차단됨: {$a}';
$string['blockedtext'] = '보안상의 이유로 이 요청이 차단되었습니다. 잘못된 차단이라고 생각되면 사이트 운영자에게 문의하세요.';
$string['blockedtitle'] = '요청이 차단되었습니다';
$string['blockrefused'] = '차단하지 않았습니다. 값이 올바르지 않거나, 관리자 것이거나, 본인 주소입니다.';
$string['blocks'] = '차단된 주소';
$string['blockvalue'] = 'IP 또는 범위 (예: 203.0.113.0/24)';
$string['coldata'] = '데이터';
$string['coldate'] = '날짜 (UTC)';
$string['colemail'] = '이메일';
$string['colip'] = '주소';
$string['colmessage'] = '메시지';
$string['colreason'] = '사유';
$string['colsigns'] = '징후';
$string['coluntil'] = '만료 (UTC)';
$string['colvalue'] = '주소 또는 이메일';
$string['colverdict'] = '판정';
$string['colwhere'] = '적용 범위';
$string['days15'] = '15일';
$string['days30'] = '30일';
$string['days7'] = '7일';
$string['days90'] = '90일';
$string['done'] = '완료.';
$string['dracoinsomnis:bypassfirewall'] = 'Draco Insomnis 방화벽 우회';
$string['events'] = '최근의 의심스러운 시도';
$string['events_help'] = '90일간 보관됩니다. 비밀번호는 절대 저장하지 않습니다. 주소별 CSV에는 그 주소가 한 모든 일이 담겨 있어, 네트워크 제공자에게 보내는 악용 신고에 바로 첨부할 수 있습니다.';
$string['evidence'] = 'Draco Insomnis: 차단과 증거';
$string['forever'] = '영구';
$string['geo'] = '국가';
$string['geo_desc'] = '방문자는 여러 나라에서 올 수 있고, 공격자는 VPN으로 나라를 바꿉니다. 로그인, 가입, 양식만 거르고 ‘기록만’으로 시작하세요. 사이트 관리자, 통과시킨 사람, 검색 엔진은 거르지 않습니다. 방화벽이 켜져 있어야 합니다(기록 또는 차단).';
$string['geoaction'] = '동작';
$string['geocountries'] = '국가 (두 글자 코드, 예: ES, FR, DE)';
$string['geocredit'] = 'IP 위치 정보는 DB-IP(db-ip.com, CC BY 4.0)를 사용하며, 필터를 켤 때 내려받아 내 서버에서 조회합니다. 어떤 주소도 외부로 보내지 않습니다.';
$string['geomode'] = '필터';
$string['geoonly'] = '목록의 국가만';
$string['georefuse'] = '목록의 국가 거부';
$string['geoscope'] = '적용 범위';
$string['geosensitive'] = '로그인, 가입, 양식 (권장)';
$string['geosite'] = '사이트 전체';
$string['headers'] = '보안 헤더';
$string['headers_desc'] = '페이지에서: 파일 형식 추측 금지, 다른 사이트에 삽입 금지, 출처 정보 축소, 삽입된 콘텐츠의 카메라·마이크·위치 사용 금지. Moodle이 이미 보내는 헤더는 다시 보내지 않습니다.';
$string['hsts'] = '6개월간 HTTPS 강제(HSTS)';
$string['hsts_desc'] = '사이트 전체가 HTTPS로 작동하고 앞으로도 그럴 때만. 브라우저가 이를 기억하고 만료될 때까지 HTTP를 거부합니다.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> 캡차 없이 가짜 가입을 막습니다. 봇은 계정을 얻지 못하고, 의심스러운 시도는 모두 악용 신고를 위한 증거로 90일간 보관됩니다. 공격자에게는 아무것도 돌려보내지 않습니다.</p><p>차단된 주소와 최근 시도: <a href="{$a}">Draco Insomnis: 차단과 증거</a>.</p>';
$string['modeblock'] = '차단';
$string['modelog'] = '기록만: 막았을 것을 기록';
$string['modeoff'] = '끔';
$string['nets'] = '임대 서버 네트워크';
$string['nets_desc'] = '한 줄에 범위 하나(CIDR). 플러그인이 이미 아는 범위에 더해집니다. 이 목록에 있으면 점수만 더해질 뿐, 그것만으로 누군가를 봇으로 판정하지는 않습니다.';
$string['noblocks'] = '현재 차단된 것이 없습니다.';
$string['noevents'] = '아직 없습니다.';
$string['noreviews'] = '요청이 없습니다.';
$string['notdone'] = '그 주소에는 할 수 없었습니다.';
$string['pace'] = '복제 방지 속도 제한';
$string['pace_desc'] = '사람이 읽는 것보다 많은 페이지를 1분에 요청하면 그 1분이 끝날 때까지 ‘429 Too many requests’를 받습니다. 로그인한 사용자, 내 주소, DNS로 확인된 검색 엔진(Google, Bing, Apple, Yandex)은 제한하지 않습니다. AJAX 호출, 웹 서비스, 파일은 세지 않습니다.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = '자동 차단이나 관리자에 의해 일정 기간 차단된 주소와 이메일.';
$string['privacy:metadata:blocks:value'] = '차단된 IP 주소 또는 이메일.';
$string['privacy:metadata:events'] = '의심스러운 시도(가짜 가입, 공격, 대량 수집). 악용 신고를 위한 증거로 90일간 보관됩니다. Moodle 계정과 연결되지 않습니다. 비밀번호는 절대 저장하지 않습니다.';
$string['privacy:metadata:events:fields'] = '시도와 함께 보낸 사용자 이름, 이메일, 참조 페이지.';
$string['privacy:metadata:events:ip'] = '시도가 온 IP 주소.';
$string['privacy:metadata:events:timecreated'] = '시도가 일어난 시각.';
$string['privacy:metadata:events:useragent'] = '보낸 브라우저나 프로그램의 이름.';
$string['proxy'] = '방문자 주소';
$string['proxy_desc'] = '사이트가 프록시 뒤에 있지 않다면 ‘연결 주소’를 그대로 두세요. 헤더는 누구나 위조할 수 있습니다.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = '헤더를 무시합니다: 이 연결(<code>{$a}</code>)은 Cloudflare나 신뢰하는 프록시에서 오지 않았습니다. 프록시가 인터넷에 있다면 그 주소를 ‘신뢰하는 프록시’에 추가하세요.';
$string['proxynone'] = '연결 주소(권장)';
$string['proxyxff'] = '기타 프록시 (X-Forwarded-For)';
$string['pwdbreached'] = '데이터 유출에서 발견된 비밀번호 거부';
$string['pwdbreached_desc'] = 'k-익명성으로 Have I Been Pwned에 묻습니다. 사이트 밖으로 나가는 것은 비밀번호 SHA-1의 5자뿐이며 비밀번호 자체는 절대 나가지 않습니다. 서비스가 3초 안에 답하지 않으면 비밀번호를 받아들입니다. Moodle은 ‘비밀번호 정책’이 켜져 있는 동안 이를 적용합니다(사이트 관리 > 보안 > 사이트 보안 설정).';
$string['pwdbreachedrefused'] = '이 비밀번호는 알려진 데이터 유출에 있어 공격자가 가장 먼저 시도합니다. 다른 비밀번호를 선택하세요.';
$string['pwdmin'] = '비밀번호 최소 길이';
$string['pwdmin_desc'] = '8~64자. 0이면 Moodle 자체 규칙만 남습니다. ‘비밀번호 정책’이 켜져 있는 동안 적용됩니다.';
$string['pwdshort'] = '비밀번호는 {$a}자 이상이어야 합니다.';
$string['rateip'] = '주소당 분당 페이지 수';
$string['ratenet'] = '네트워크당 분당 페이지 수';
$string['ratenet_desc'] = 'IPv4는 /24, IPv6는 /64 네트워크: 이웃한 주소를 돌려 쓰는 스크래퍼가 얻는 범위입니다.';
$string['rejected'] = '가입을 완료할 수 없습니다.';
$string['review1'] = '24시간 통과';
$string['review30'] = '30일';
$string['review7'] = '7일';
$string['reviewapproved'] = '통과';
$string['reviewattacker'] = '공격자: 차단됨';
$string['reviewattackerbtn'] = '공격자';
$string['reviewbody'] = '방화벽에 막힌 방문자가 검토를 요청했습니다. Draco Insomnis 페이지를 열어 통과시킬지 정하세요.';
$string['reviewbutton'] = '검토 요청';
$string['reviewdenied'] = '거부됨';
$string['reviewdeny'] = '거부';
$string['reviewemail'] = '이메일';
$string['reviewmessage'] = '무엇을 하고 계셨나요?';
$string['reviewreason'] = '검토: {$a}';
$string['reviews'] = '검토 요청';
$string['reviewsenttext'] = '감사합니다. 사이트 관리자가 확인하고, 실수였다면 통과시켜 드립니다.';
$string['reviewsenttitle'] = '요청을 보냈습니다';
$string['reviewshelp'] = '방화벽에 막힌 사람은 차단 페이지에서 요청할 수 있습니다. 실수였다면 잠시 통과시켜 주세요. Draco는 그들에게 절대 메일을 보내지 않습니다. 원하면 직접 메일로 답하세요.';
$string['reviewsubject'] = '[{$a}] 방화벽 차단을 검토해 달라는 요청이 왔습니다';
$string['shield'] = '자가 등록 보호';
$string['shield_desc'] = '가입 양식(이메일 기반 자가 등록)에 보이지 않는 함정과 서명된 페이지 스탬프를 추가합니다. 봇은 계정을 얻지 못하며, 하루에 봇 시도가 세 번이면 그 주소는 일주일 동안 차단됩니다.';
$string['summary'] = '방화벽: 최근 7일';
$string['summaryips'] = '가장 활발한 주소:';
$string['summaryline'] = '공격 {$a->total}건 확인, {$a->blocked}건 차단.';
$string['summarywhat'] = '내용:';
$string['taskcleanup'] = 'Draco Insomnis: 오래된 증거와 끝난 차단 삭제';
$string['test'] = '방화벽 테스트';
$string['testblocked'] = '작동합니다: 데이터베이스 주입을 인식하고 차단했습니다(403).';
$string['testhelp'] = '공격 형태의 무해한 요청을 사이트에 보내고 결과를 알려 줍니다. 기록되지 않습니다.';
$string['testlogged'] = '작동합니다: 데이터베이스 주입을 인식했습니다. «기록만» 모드에서는 기록만 하고 막지 않습니다. 준비되면 «차단»으로 바꾸세요.';
$string['testnone'] = '테스트 공격이 인식되지 않았습니다. Draco Insomnis에 알려 주세요.';
$string['testoff'] = '방화벽이 꺼져 있습니다. 켜고 저장한 뒤 다시 테스트하세요.';
$string['testunreachable'] = '서버 자신에서 사이트에 접속하지 못했습니다(일부 호스팅은 허용하지 않습니다). 그래도 방화벽은 작동할 수 있으니 최근 시도를 확인하세요.';
$string['testupstream'] = '테스트가 Moodle에 닿기 전에 호스팅 자체 방화벽에서 막혔습니다. 좋습니다: 이중 방어입니다.';
$string['trusted'] = '신뢰하는 프록시';
$string['trusted_desc'] = '이 주소에서 오는 연결만 헤더로 방문자 주소를 지정할 수 있습니다. 한 줄에 주소나 범위 하나. 비워 두면: 이 서버와 사설 네트워크. Cloudflare 자체 범위는 이미 알고 있습니다.';
$string['unblock'] = '차단 해제';
$string['unblocked'] = '주소 차단을 해제했습니다.';
$string['waf'] = '방화벽';
$string['waf_desc'] = '공격 형태의 요청(데이터베이스 삽입, 서버 파일 읽기, 코드 실행, 링크 속 스크립트)과 sqlmap, Nikto 같은 스캐너를 막습니다. ‘기록만’으로 시작하고 며칠 뒤 ‘차단’으로 바꾸세요. 10분에 공격 5번이면 그 주소는 일주일 동안 차단되며, 차단된 주소도 사이트를 읽을 수는 있지만 전송이나 로그인은 할 수 없습니다. 사이트 관리자와 ‘Draco Insomnis 방화벽 우회’ 권한이 있는 사용자는 검사하지 않습니다. 비상구: config.php에 define(\'DRACO_WAF_OFF\', true); 를 넣으세요.';
$string['wafblock'] = '방화벽: 10분에 공격 {$a}번';
$string['yourip'] = '플러그인이 보는 내 주소: <code>{$a->ip}</code> (연결 주소: <code>{$a->remote}</code>). 사이트가 Cloudflare나 다른 프록시 뒤에 있고 이 주소가 실제 주소와 다르면 ‘방문자 주소’에서 알맞은 항목을 고르세요.';
