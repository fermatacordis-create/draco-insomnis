<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'vi' (generated from i18n/vi.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Tự động: {$a} lần thử của bot trong 24 giờ';
$string['block'] = 'Chặn';
$string['blockadd'] = 'Chặn một địa chỉ hoặc dải';
$string['blockadd_desc'] = 'Không bao giờ là quản trị viên hay địa chỉ của chính bạn. Dải không rộng hơn /16 (IPv4) hoặc /32 (IPv6).';
$string['blockdays'] = 'Trong';
$string['blockdone'] = 'Đã chặn: {$a}';
$string['blockedtext'] = 'Yêu cầu này đã bị dừng vì lý do bảo mật. Nếu bạn nghĩ đây là nhầm lẫn, hãy liên hệ chủ trang.';
$string['blockedtitle'] = 'Yêu cầu bị chặn';
$string['blockrefused'] = 'Không chặn gì: giá trị không hợp lệ, thuộc về quản trị viên, hoặc là địa chỉ của chính bạn.';
$string['blocks'] = 'Địa chỉ bị chặn';
$string['blockvalue'] = 'IP hoặc dải (ví dụ 203.0.113.0/24)';
$string['coldata'] = 'Dữ liệu';
$string['coldate'] = 'Ngày (UTC)';
$string['colemail'] = 'Email';
$string['colip'] = 'Địa chỉ';
$string['colmessage'] = 'Tin nhắn';
$string['colreason'] = 'Lý do';
$string['colsigns'] = 'Dấu hiệu';
$string['coluntil'] = 'Đến (UTC)';
$string['colvalue'] = 'Địa chỉ hoặc email';
$string['colverdict'] = 'Kết luận';
$string['colwhere'] = 'Ở đâu';
$string['days15'] = '15 ngày';
$string['days30'] = '30 ngày';
$string['days7'] = '7 ngày';
$string['days90'] = '90 ngày';
$string['done'] = 'Xong.';
$string['dracoinsomnis:bypassfirewall'] = 'Bỏ qua tường lửa Draco Insomnis';
$string['events'] = 'Các lần thử đáng ngờ gần đây';
$string['events_help'] = 'Lưu 90 ngày. Không bao giờ lưu mật khẩu. CSV của một địa chỉ chứa mọi thứ nó đã làm, sẵn sàng đính kèm vào báo cáo lạm dụng gửi nhà cung cấp mạng của nó.';
$string['evidence'] = 'Draco Insomnis: chặn và bằng chứng';
$string['forever'] = 'Vĩnh viễn';
$string['geo'] = 'Quốc gia';
$string['geo_desc'] = 'Khách truy cập của bạn có thể đến từ nhiều quốc gia, và kẻ tấn công đổi quốc gia bằng VPN. Chỉ lọc đăng nhập, đăng ký và biểu mẫu, và bắt đầu với “Chỉ ghi lại”. Quản trị viên trang, người bạn cho qua và công cụ tìm kiếm không bao giờ bị lọc. Cần bật tường lửa (ghi lại hoặc chặn).';
$string['geoaction'] = 'Làm gì';
$string['geocountries'] = 'Quốc gia (mã hai chữ cái, ví dụ ES, FR, DE)';
$string['geocredit'] = 'Định vị IP do DB-IP cung cấp (db-ip.com, CC BY 4.0), được tải về khi bạn bật bộ lọc và tra cứu ngay trên máy chủ của bạn: không có địa chỉ nào được gửi đi đâu cả.';
$string['geomode'] = 'Bộ lọc';
$string['geoonly'] = 'Chỉ các quốc gia trong danh sách';
$string['georefuse'] = 'Từ chối các quốc gia trong danh sách';
$string['geoscope'] = 'Ở đâu';
$string['geosensitive'] = 'Đăng nhập, đăng ký và biểu mẫu (khuyên dùng)';
$string['geosite'] = 'Toàn bộ trang';
$string['headers'] = 'Header bảo mật';
$string['headers_desc'] = 'Trên các trang: không đoán loại tệp, không cho trang khác nhúng, ít dữ liệu nguồn giới thiệu hơn, không có camera, micrô hay vị trí cho nội dung nhúng. Không bao giờ gửi lại header Moodle đã gửi.';
$string['hsts'] = 'Buộc dùng HTTPS trong 6 tháng (HSTS)';
$string['hsts_desc'] = 'Chỉ khi toàn bộ trang chạy trên HTTPS và sẽ tiếp tục như vậy: trình duyệt ghi nhớ và từ chối HTTP cho đến khi hết hạn.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Chặn đăng ký giả mà không cần captcha: bot không có được tài khoản, và mọi lần thử đáng ngờ được lưu 90 ngày làm bằng chứng cho báo cáo lạm dụng. Không bao giờ gửi lại gì cho kẻ tấn công.</p><p>Địa chỉ bị chặn và các lần thử gần đây: <a href="{$a}">Draco Insomnis: chặn và bằng chứng</a>.</p>';
$string['modeblock'] = 'Chặn';
$string['modelog'] = 'Chỉ ghi lại: ghi lại những gì sẽ bị chặn';
$string['modeoff'] = 'Tắt';
$string['nets'] = 'Mạng máy chủ thuê';
$string['nets_desc'] = 'Mỗi dòng một dải (CIDR), được thêm vào các dải plugin đã biết. Có tên trong danh sách này chỉ cộng thêm điểm: tự nó không bao giờ biến ai thành bot.';
$string['noblocks'] = 'Hiện không có gì bị chặn.';
$string['noevents'] = 'Chưa có gì.';
$string['noreviews'] = 'Không có yêu cầu.';
$string['notdone'] = 'Không thể thực hiện cho địa chỉ đó.';
$string['pace'] = 'Giới hạn tốc độ chống sao chép';
$string['pace_desc'] = 'Ai yêu cầu nhiều trang mỗi phút hơn lượng một người đọc sẽ nhận “429 Too many requests” cho đến hết phút đó. Người dùng đã đăng nhập, địa chỉ của chính bạn và công cụ tìm kiếm được xác minh qua DNS (Google, Bing, Apple, Yandex) không bao giờ bị giới hạn. Lệnh gọi AJAX, dịch vụ web và tệp không được tính.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Địa chỉ và email bị chặn một thời gian, bởi tính năng chặn tự động hoặc bởi quản trị viên.';
$string['privacy:metadata:blocks:value'] = 'Địa chỉ IP hoặc email bị chặn.';
$string['privacy:metadata:events'] = 'Các lần thử đáng ngờ (đăng ký giả, tấn công, cào dữ liệu), lưu 90 ngày làm bằng chứng cho báo cáo lạm dụng. Không liên kết với tài khoản Moodle. Không bao giờ lưu mật khẩu.';
$string['privacy:metadata:events:fields'] = 'Tên người dùng, email và trang giới thiệu được gửi kèm lần thử.';
$string['privacy:metadata:events:ip'] = 'Địa chỉ IP mà lần thử xuất phát.';
$string['privacy:metadata:events:timecreated'] = 'Thời điểm lần thử xảy ra.';
$string['privacy:metadata:events:useragent'] = 'Tên trình duyệt hoặc chương trình mà nó gửi.';
$string['proxy'] = 'Địa chỉ khách truy cập';
$string['proxy_desc'] = 'Giữ “Địa chỉ kết nối” trừ khi trang nằm sau một proxy: ai cũng có thể giả mạo một header.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'Header bị bỏ qua: kết nối này (<code>{$a}</code>) không đến từ Cloudflare hay một proxy tin cậy. Nếu proxy của bạn nằm trên internet, hãy thêm địa chỉ của nó vào “Proxy tin cậy”.';
$string['proxynone'] = 'Địa chỉ kết nối (khuyên dùng)';
$string['proxyxff'] = 'Proxy khác (X-Forwarded-For)';
$string['pwdbreached'] = 'Từ chối mật khẩu đã xuất hiện trong các vụ rò rỉ dữ liệu';
$string['pwdbreached_desc'] = 'Hỏi Have I Been Pwned theo k-ẩn danh: chỉ 5 ký tự của SHA-1 mật khẩu rời khỏi trang, không bao giờ là mật khẩu. Nếu dịch vụ không trả lời trong 3 giây, mật khẩu được chấp nhận. Moodle áp dụng điều này khi “Chính sách mật khẩu” đang bật (Quản trị trang > Bảo mật > Cài đặt bảo mật trang).';
$string['pwdbreachedrefused'] = 'Mật khẩu này có trong các vụ rò rỉ dữ liệu đã biết, nên kẻ tấn công thử nó trước tiên. Vui lòng chọn mật khẩu khác.';
$string['pwdmin'] = 'Độ dài tối thiểu của mật khẩu';
$string['pwdmin_desc'] = 'Từ 8 đến 64 ký tự; 0 chỉ giữ quy tắc riêng của Moodle. Áp dụng khi “Chính sách mật khẩu” đang bật.';
$string['pwdshort'] = 'Mật khẩu phải có ít nhất {$a} ký tự.';
$string['rateip'] = 'Số trang mỗi phút, theo địa chỉ';
$string['ratenet'] = 'Số trang mỗi phút, theo mạng';
$string['ratenet_desc'] = 'Một mạng /24 với IPv4 hoặc /64 với IPv6: phạm vi một công cụ cào dữ liệu có được khi xoay vòng các địa chỉ liền kề.';
$string['rejected'] = 'Không thể hoàn tất đăng ký.';
$string['review1'] = 'Cho qua 24 giờ';
$string['review30'] = '30 ngày';
$string['review7'] = '7 ngày';
$string['reviewapproved'] = 'Cho qua';
$string['reviewattacker'] = 'Kẻ tấn công: đã chặn';
$string['reviewattackerbtn'] = 'Kẻ tấn công';
$string['reviewbody'] = 'Một khách truy cập bị tường lửa chặn đang yêu cầu xem xét. Mở trang Draco Insomnis để cho qua hoặc không.';
$string['reviewbutton'] = 'Yêu cầu xem xét lại';
$string['reviewdenied'] = 'Đã từ chối';
$string['reviewdeny'] = 'Từ chối';
$string['reviewemail'] = 'Email của bạn';
$string['reviewmessage'] = 'Bạn đang làm gì?';
$string['reviewreason'] = 'Xem xét: {$a}';
$string['reviews'] = 'Yêu cầu xem xét';
$string['reviewsenttext'] = 'Cảm ơn bạn. Chủ trang sẽ xem xét và, nếu là nhầm lẫn, sẽ cho bạn qua.';
$string['reviewsenttitle'] = 'Đã gửi yêu cầu';
$string['reviewshelp'] = 'Người bị tường lửa chặn có thể yêu cầu từ trang chặn. Hãy cho họ qua một thời gian nếu là nhầm lẫn. Draco không bao giờ viết thư cho họ: hãy trả lời từ email của bạn nếu muốn.';
$string['reviewsubject'] = '[{$a}] Có người nhờ bạn xem xét một lần chặn của tường lửa';
$string['shield'] = 'Bảo vệ tự đăng ký';
$string['shield_desc'] = 'Thêm một cái bẫy vô hình và một con dấu trang có chữ ký vào biểu mẫu đăng ký (tự đăng ký qua email). Bot không có được tài khoản; ba lần thử của bot trong một ngày sẽ chặn địa chỉ trong một tuần.';
$string['summary'] = 'Tường lửa: 7 ngày qua';
$string['summaryips'] = 'Địa chỉ hoạt động nhiều nhất:';
$string['summaryline'] = 'Thấy {$a->total} cuộc tấn công, đã chặn {$a->blocked}.';
$string['summarywhat'] = 'Gì:';
$string['taskcleanup'] = 'Draco Insomnis: xóa bằng chứng cũ và các lần chặn đã hết hạn';
$string['test'] = 'Thử tường lửa';
$string['testblocked'] = 'Hoạt động: đã nhận ra một lần chèn vào cơ sở dữ liệu và chặn nó (403).';
$string['testhelp'] = 'Gửi tới trang một yêu cầu vô hại có hình dạng tấn công và cho bạn biết điều gì đã xảy ra. Không được ghi lại.';
$string['testlogged'] = 'Hoạt động: đã nhận ra một lần chèn vào cơ sở dữ liệu. Ở "Chỉ ghi lại" nó được ghi nhưng không bị chặn; hãy chuyển sang "Chặn" khi bạn sẵn sàng.';
$string['testnone'] = 'Không nhận ra cuộc tấn công thử. Vui lòng báo cho Draco Insomnis.';
$string['testoff'] = 'Tường lửa đang tắt: hãy bật, lưu rồi thử lại.';
$string['testunreachable'] = 'Bài thử không thể kết nối tới trang từ chính máy chủ (một số dịch vụ lưu trữ không cho phép). Tường lửa vẫn có thể đang hoạt động: hãy xem các lần thử gần đây.';
$string['testupstream'] = 'Bài thử đã bị tường lửa của chính dịch vụ lưu trữ chặn trước khi tới Moodle. Tốt: hai lớp.';
$string['trusted'] = 'Proxy tin cậy';
$string['trusted_desc'] = 'Chỉ các kết nối từ những địa chỉ này mới được đặt địa chỉ khách truy cập qua header. Mỗi dòng một địa chỉ hoặc dải. Để trống: máy chủ này và các mạng riêng. Các dải của Cloudflare đã được biết sẵn.';
$string['unblock'] = 'Bỏ chặn';
$string['unblocked'] = 'Đã bỏ chặn địa chỉ.';
$string['waf'] = 'Tường lửa';
$string['waf_desc'] = 'Chặn các yêu cầu có dạng tấn công (chèn vào cơ sở dữ liệu, đọc tệp máy chủ, chạy mã, script trong liên kết) và các công cụ quét như sqlmap hay Nikto. Hãy bắt đầu với “Chỉ ghi lại” và chuyển sang “Chặn” sau vài ngày. Năm cuộc tấn công trong 10 phút sẽ chặn địa chỉ một tuần; địa chỉ bị chặn vẫn đọc được trang nhưng không gửi được và không đăng nhập được. Quản trị viên trang và người dùng có quyền “Bỏ qua tường lửa Draco Insomnis” không bao giờ bị kiểm tra. Lối thoát khẩn cấp: define(\'DRACO_WAF_OFF\', true); trong config.php.';
$string['wafblock'] = 'Tường lửa: {$a} cuộc tấn công trong 10 phút';
$string['yourip'] = 'Địa chỉ của bạn theo plugin thấy: <code>{$a->ip}</code> (địa chỉ kết nối: <code>{$a->remote}</code>). Nếu trang web nằm sau Cloudflare hoặc proxy khác và hai địa chỉ này khác địa chỉ thật của bạn, hãy chọn tùy chọn phù hợp trong “Địa chỉ khách truy cập”.';
