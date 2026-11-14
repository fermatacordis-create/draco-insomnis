<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'ja' (generated from i18n/ja.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = '自動: 24 時間でボットの試行 {$a} 回';
$string['block'] = 'ブロック';
$string['blockadd'] = 'アドレスまたは範囲をブロックする';
$string['blockadd_desc'] = '管理者やあなた自身のアドレスは対象外です。範囲は /16（IPv4）または /32（IPv6）より広くできません。';
$string['blockdays'] = '期間';
$string['blockdone'] = 'ブロックしました: {$a}';
$string['blockedtext'] = 'このリクエストはセキュリティ上の理由で止められました。誤りだと思われる場合は、サイトの管理者に連絡してください。';
$string['blockedtitle'] = 'リクエストがブロックされました';
$string['blockrefused'] = '何もブロックされませんでした。値が無効か、管理者のものか、あなた自身のアドレスです。';
$string['blocks'] = 'ブロック中のアドレス';
$string['blockvalue'] = 'IP または範囲（例: 203.0.113.0/24）';
$string['coldata'] = 'データ';
$string['coldate'] = '日時 (UTC)';
$string['colemail'] = 'メール';
$string['colip'] = 'アドレス';
$string['colmessage'] = 'メッセージ';
$string['colreason'] = '理由';
$string['colsigns'] = '兆候';
$string['coluntil'] = '期限 (UTC)';
$string['colvalue'] = 'アドレスまたはメールアドレス';
$string['colverdict'] = '判定';
$string['colwhere'] = '対象';
$string['days15'] = '15 日';
$string['days30'] = '30 日';
$string['days7'] = '7 日';
$string['days90'] = '90 日';
$string['done'] = '完了しました。';
$string['dracoinsomnis:bypassfirewall'] = 'Draco Insomnis のファイアウォールを通過する';
$string['events'] = '最近の疑わしい試行';
$string['events_help'] = '90 日間保存されます。パスワードは保存しません。アドレスごとの CSV にはそのアドレスの行動がすべて含まれ、そのままネットワーク事業者への不正利用の報告に添付できます。';
$string['evidence'] = 'Draco Insomnis: ブロックと証拠';
$string['forever'] = '無期限';
$string['geo'] = '国';
$string['geo_desc'] = '訪問者は多くの国から来る可能性があり、攻撃者は VPN で国を変えます。ログイン、登録、フォームだけを対象にし、まず「記録のみ」で始めてください。サイト管理者、あなたが通した人、検索エンジンはフィルタされません。ファイアウォールを有効（記録またはブロック）にする必要があります。';
$string['geoaction'] = '動作';
$string['geocountries'] = '国（2 文字コード。例: ES, FR, DE）';
$string['geocredit'] = 'IP の位置情報は DB-IP（db-ip.com、CC BY 4.0）によるもので、フィルタを有効にしたときにダウンロードされ、あなたのサーバー上で照合されます。アドレスがどこかへ送られることはありません。';
$string['geomode'] = 'フィルター';
$string['geoonly'] = 'リストの国のみ';
$string['georefuse'] = 'リストの国を拒否';
$string['geoscope'] = '対象';
$string['geosensitive'] = 'ログイン、登録、フォーム（推奨）';
$string['geosite'] = 'サイト全体';
$string['headers'] = 'セキュリティヘッダー';
$string['headers_desc'] = 'ページで: ファイル形式の推測をさせない、他サイトへの埋め込みを許さない、参照元の情報を減らす、埋め込みコンテンツにカメラ・マイク・位置情報を使わせない。Moodle が既に送っているものは重ねて送りません。';
$string['hsts'] = 'HTTPS を 6 か月間強制する（HSTS）';
$string['hsts_desc'] = 'サイト全体が HTTPS で動作し、今後もそうである場合のみ。ブラウザはこれを記憶し、期限が切れるまで HTTP を拒否します。';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> CAPTCHA なしで偽の登録を止めます。ボットはアカウントを得られず、疑わしい試行はすべて不正利用の報告用の証拠として 90 日間保存されます。攻撃者に何かを送り返すことはありません。</p><p>ブロック中のアドレスと最近の試行: <a href="{$a}">Draco Insomnis: ブロックと証拠</a>。</p>';
$string['modeblock'] = 'ブロック';
$string['modelog'] = '記録のみ: 止めるはずだったものを記録';
$string['modeoff'] = 'オフ';
$string['nets'] = 'レンタルサーバーのネットワーク';
$string['nets_desc'] = '1 行に 1 つの範囲（CIDR）。プラグインが既に知っている範囲に追加されます。このリストに載っていても点数が加わるだけで、それだけでボットと判定されることはありません。';
$string['noblocks'] = '現在ブロックしているものはありません。';
$string['noevents'] = 'まだありません。';
$string['noreviews'] = '依頼はありません。';
$string['notdone'] = 'そのアドレスではできませんでした。';
$string['pace'] = 'コピー対策の速度制限';
$string['pace_desc'] = '人が読める以上のページを 1 分間に要求すると、その 1 分が終わるまで「429 Too many requests」が返されます。ログイン中のユーザー、あなた自身のアドレス、DNS で確認された検索エンジン（Google、Bing、Apple、Yandex）は制限されません。AJAX 呼び出し、Web サービス、ファイルは数えません。';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = '自動ブロックまたは管理者によって一定期間ブロックされたアドレスとメールアドレス。';
$string['privacy:metadata:blocks:value'] = 'ブロックされた IP アドレスまたはメールアドレス。';
$string['privacy:metadata:events'] = '疑わしい試行（偽の登録、攻撃、大量コピー）。不正利用の報告用の証拠として 90 日間保存されます。Moodle のアカウントとは結び付けられません。パスワードは保存しません。';
$string['privacy:metadata:events:fields'] = '試行と一緒に送られたユーザー名、メールアドレス、参照元ページ。';
$string['privacy:metadata:events:ip'] = '試行の送信元 IP アドレス。';
$string['privacy:metadata:events:timecreated'] = '試行が起きた日時。';
$string['privacy:metadata:events:useragent'] = '送信されたブラウザまたはプログラムの名前。';
$string['proxy'] = '訪問者のアドレス';
$string['proxy_desc'] = 'サイトがプロキシの背後にない限り「接続元アドレス」のままにしてください。ヘッダーは誰でも偽装できます。';
$string['proxycf'] = 'Cloudflare（CF-Connecting-IP）';
$string['proxyignored'] = 'ヘッダーは無視されます: この接続（<code>{$a}</code>）は Cloudflare からも信頼するプロキシからも来ていません。プロキシがインターネット上にある場合は、「信頼するプロキシ」にそのアドレスを追加してください。';
$string['proxynone'] = '接続元アドレス（推奨）';
$string['proxyxff'] = 'その他のプロキシ（X-Forwarded-For）';
$string['pwdbreached'] = 'データ漏えいで見つかったパスワードを拒否する';
$string['pwdbreached_desc'] = 'k-匿名性で Have I Been Pwned に問い合わせます。サイトから出るのはパスワードの SHA-1 の 5 文字だけで、パスワードそのものは送りません。3 秒以内に応答がなければ、パスワードは受け入れられます。Moodle は「パスワードポリシー」が有効な間これを適用します（サイト管理 > セキュリティ > サイトセキュリティ設定）。';
$string['pwdbreachedrefused'] = 'このパスワードは既知のデータ漏洩に含まれているため、攻撃者が最初に試します。別のパスワードを選んでください。';
$string['pwdmin'] = 'パスワードの最小文字数';
$string['pwdmin_desc'] = '8～64 文字。0 にすると Moodle 自身の規則だけが残ります。「パスワードポリシー」が有効な間に適用されます。';
$string['pwdshort'] = 'パスワードは {$a} 文字以上にしてください。';
$string['rateip'] = '1 分あたりのページ数（アドレスごと）';
$string['ratenet'] = '1 分あたりのページ数（ネットワークごと）';
$string['ratenet_desc'] = 'IPv4 なら /24、IPv6 なら /64 のネットワーク: 隣り合うアドレスを渡り歩くスクレイパーが使える範囲です。';
$string['rejected'] = '登録を完了できませんでした。';
$string['review1'] = '24 時間通す';
$string['review30'] = '30 日';
$string['review7'] = '7 日';
$string['reviewapproved'] = '通す';
$string['reviewattacker'] = '攻撃者: ブロック済み';
$string['reviewattackerbtn'] = '攻撃者';
$string['reviewbody'] = 'ファイアウォールに止められた訪問者が確認を依頼しています。Draco Insomnis のページを開いて、通すかどうか決めてください。';
$string['reviewbutton'] = '確認を依頼する';
$string['reviewdenied'] = '拒否済み';
$string['reviewdeny'] = '拒否';
$string['reviewemail'] = 'メールアドレス';
$string['reviewmessage'] = '何をしていましたか？';
$string['reviewreason'] = '確認: {$a}';
$string['reviews'] = '確認依頼';
$string['reviewsenttext'] = 'ありがとうございます。サイトの管理者が確認し、誤りであれば通れるようにします。';
$string['reviewsenttitle'] = '送信しました';
$string['reviewshelp'] = 'ファイアウォールに止められた人はブロックページから依頼できます。誤りなら一定期間通してください。Draco から相手に連絡することはありません。必要ならご自身のメールで返信してください。';
$string['reviewsubject'] = '[{$a}] ファイアウォールのブロックの確認を依頼されています';
$string['shield'] = '自己登録を保護する';
$string['shield_desc'] = '登録フォーム（メールによる自己登録）に見えない罠と署名付きのページスタンプを加えます。ボットはアカウントを得られず、1 日に 3 回ボットと判定されたアドレスは 1 週間ブロックされます。';
$string['summary'] = 'ファイアウォール: 過去 7 日間';
$string['summaryips'] = '最も活発なアドレス:';
$string['summaryline'] = '攻撃 {$a->total} 件を検出、{$a->blocked} 件をブロック。';
$string['summarywhat'] = '内容:';
$string['taskcleanup'] = 'Draco Insomnis: 古い証拠と期限切れのブロックを削除';
$string['test'] = 'ファイアウォールをテスト';
$string['testblocked'] = '動作しています: データベースへのインジェクションを認識してブロックしました（403）。';
$string['testhelp'] = '攻撃の形をした無害なリクエストをサイトに送り、結果を表示します。記録はされません。';
$string['testlogged'] = '動作しています: データベースへのインジェクションを認識しました。「記録のみ」では記録されますが止めません。準備ができたら「ブロック」に切り替えてください。';
$string['testnone'] = 'テスト攻撃が認識されませんでした。Draco Insomnis に報告してください。';
$string['testoff'] = 'ファイアウォールはオフです。オンにして保存し、もう一度テストしてください。';
$string['testunreachable'] = 'サーバー自身からサイトに到達できませんでした（一部のホスティングでは許可されていません）。それでもファイアウォールは動作している可能性があります。最近の試行を確認してください。';
$string['testupstream'] = 'テストは Moodle に届く前に、ホスティング側のファイアウォールで止められました。良好です: 二重の防御です。';
$string['trusted'] = '信頼するプロキシ';
$string['trusted_desc'] = 'これらのアドレスからの接続だけが、ヘッダーで訪問者のアドレスを指定できます。1 行に 1 つのアドレスまたは範囲。空欄: このサーバーとプライベートネットワーク。Cloudflare 自身の範囲は既に登録済みです。';
$string['unblock'] = 'ブロック解除';
$string['unblocked'] = 'アドレスのブロックを解除しました。';
$string['waf'] = 'ファイアウォール';
$string['waf_desc'] = '攻撃の形をしたリクエスト（データベースへのインジェクション、サーバーファイルの読み取り、コードの実行、リンク内のスクリプト）と、sqlmap や Nikto などのスキャナーを止めます。まず「記録のみ」で始め、数日後に「ブロック」に切り替えてください。10 分間に 5 回の攻撃でそのアドレスは 1 週間ブロックされます。ブロックされたアドレスもサイトの閲覧はできますが、送信やログインはできません。サイト管理者と「Draco Insomnis のファイアウォールを通過する」権限を持つユーザーは検査されません。非常口: config.php に define(\'DRACO_WAF_OFF\', true); と書きます。';
$string['wafblock'] = 'ファイアウォール: 10 分間で攻撃 {$a} 回';
$string['yourip'] = 'プラグインから見たあなたのアドレス: <code>{$a->ip}</code>（接続元アドレス: <code>{$a->remote}</code>）。サイトが Cloudflare などのプロキシの背後にあり、これらが実際のアドレスと異なる場合は、「訪問者のアドレス」で該当する項目を選んでください。';
