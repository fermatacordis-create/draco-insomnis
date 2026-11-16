<?php

declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Gate\LinkCheck;

/** Malicious links (URLhaus): the local index, exact matching, comments and contact forms. No network. */
final class LinkCheckTest extends TestCase
{
    private const EXPORT = <<<'CSV'
################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs)             #
################################################################
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3000001","2026-11-16 08:00:00","http://bad.example/payload/loader.exe","online","2026-11-16 08:00:00","malware_download","exe","https://urlhaus.abuse.ch/url/3000001/","someone"
"3000002","2026-11-16 08:05:00","HTTPS://Hacked.Example:443/wp-content/uploads/x.zip#frag","online","2026-11-16 08:05:00","malware_download","zip","https://urlhaus.abuse.ch/url/3000002/","someone"
"3000003","2026-11-16 08:10:00","http://203.0.113.66:8080/i","online","2026-11-16 08:10:00","malware_download","elf","https://urlhaus.abuse.ch/url/3000003/","someone"
CSV;

    protected function setUp(): void
    {
        parent::setUp();
        $built = LinkCheck::buildIndex(self::EXPORT);
        wp_mkdir_p(dirname(LinkCheck::indexFile()));
        file_put_contents(LinkCheck::indexFile(), $built['index']);
        wp_set_current_user(0);
        unset($_POST['_wpcf7']);
    }

    protected function tearDown(): void
    {
        @unlink(LinkCheck::indexFile());
        unset($_POST['_wpcf7']);
        parent::tearDown();
    }

    public function test_normalize_and_links(): void
    {
        $this->assertSame('https://hacked.example/wp-content/uploads/x.zip', LinkCheck::normalize('HTTPS://Hacked.Example:443/wp-content/uploads/x.zip#frag'));
        $this->assertSame('http://bad.example/', LinkCheck::normalize('http://bad.example'));
        $this->assertSame('', LinkCheck::normalize('ftp://bad.example/x'));
        $this->assertSame(['http://a.example/x', 'https://b.example/y?z=1'], LinkCheck::links('see http://a.example/x, and (https://b.example/y?z=1).'));
    }

    public function test_index_counts_urls_and_ip_hosts(): void
    {
        // 3 URLs, plus the bare-IP host of the third one.
        $this->assertSame(4, LinkCheck::buildIndex(self::EXPORT)['count']);
        $this->assertSame(0, LinkCheck::buildIndex("# only comments\n\n")['count']);
        $this->assertSame(1, LinkCheck::buildIndex("http://one.example/a\n")['count'], 'plain text, one URL per line');
    }

    public function test_exact_urls_match_not_whole_domains(): void
    {
        $this->assertSame('http://bad.example/payload/loader.exe', LinkCheck::listed('Free stuff at http://bad.example/payload/loader.exe !'));
        $this->assertSame('https://hacked.example/wp-content/uploads/x.zip', LinkCheck::listed('https://hacked.example/wp-content/uploads/x.zip'));
        // A hacked legitimate site: its other pages are not blocked.
        $this->assertSame('', LinkCheck::listed('Nice post on https://hacked.example/blog/hello'));
        // A bare IP serving malware is listed as a whole.
        $this->assertSame('http://203.0.113.66/other', LinkCheck::listed('http://203.0.113.66/other'));
        $this->assertSame('', LinkCheck::listed('nothing here, or https://wordpress.org/'));
    }

    public function test_comment_with_listed_link_goes_to_spam(): void
    {
        $bad = ['comment_content' => 'Download http://bad.example/payload/loader.exe', 'comment_author_url' => ''];
        $this->assertSame('spam', LinkCheck::comment(0, $bad));
        $this->assertSame(0, LinkCheck::comment(0, ['comment_content' => 'A kind word and https://wordpress.org/', 'comment_author_url' => '']));
        $this->assertSame('spam', LinkCheck::comment(0, ['comment_content' => 'hi', 'comment_author_url' => 'http://203.0.113.66/']));
    }

    public function test_contact_message_with_listed_link_is_not_delivered(): void
    {
        $_POST['_wpcf7'] = '12';
        $this->assertTrue(LinkCheck::mail(null, ['to' => 'owner@example.org', 'subject' => 'Hello', 'message' => 'Look: http://bad.example/payload/loader.exe']));
        $this->assertNull(LinkCheck::mail(null, ['to' => 'owner@example.org', 'subject' => 'Hello', 'message' => 'A real question']));
        unset($_POST['_wpcf7']);
        // Mail that is not a form submission (orders, notices) is never touched.
        $this->assertNull(LinkCheck::mail(null, ['to' => 'owner@example.org', 'subject' => 'Order', 'message' => 'http://bad.example/payload/loader.exe']));
    }

    public function test_off_without_key_or_confirmation(): void
    {
        update_option(LinkCheck::OPTION_ENABLED, 'yes');
        update_option(LinkCheck::OPTION_CONFIRMED, 'yes');
        $this->assertFalse(LinkCheck::hasKey());
        $this->assertFalse(LinkCheck::active(), 'no key in wp-config.php');
        $this->assertSame('no key', LinkCheck::update());
        update_option(LinkCheck::OPTION_ENABLED, 'no');
        update_option(LinkCheck::OPTION_CONFIRMED, 'no');
    }
}
