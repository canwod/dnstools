<?php
// index.php
function getWhois($domain) {
    $apiKey = 'at_qGWGtINLxnrYKQr7ZcB8mSd0BYva2'; // WhoisXMLAPI anahtarınız
    $url = "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=$apiKey&domainName=" . urlencode($domain) . "&outputFormat=JSON";
    $response = @file_get_contents($url);
    if ($response === false) return '';
    $data = json_decode($response, true);
    if (isset($data['WhoisRecord']['rawText'])) {
        return $data['WhoisRecord']['rawText'];
    } else {
        return '';
    }
}

function getRdap($domain) {
    $url = "https://rdap.org/domain/" . urlencode($domain);
    $response = @file_get_contents($url);
    if ($response === false) return [];
    $data = json_decode($response, true);
    return $data;
}

function getDnsRecords($domain) {
    $types = ['A', 'CNAME', 'NS', 'MX', 'SOA', 'TXT'];
    $records = [];
    foreach ($types as $type) {
        $dns = @dns_get_record($domain, constant('DNS_' . $type));
        $records[$type] = $dns;
    }
    return $records;
}

function parseWhois($whois) {
    $data = [
        'Alan Adı' => '',
        'Alan Adı Durumu' => '',
        'Kaydedici Firma' => '',
        'Kaydedici WHOIS' => '',
        'Kaydedici URL' => '',
        'Kaydedici IANA ID' => '',
        'Kötüye Kullanım Mail' => '',
        'Kötüye Kullanım Telefon' => '',
        'Alan Adı Kayıt Tarihi' => '',
        'Alan Adı Bitiş Tarihi' => '',
        'Alan Adı Güncelleme Tarihi' => '',
        'Alan Adı Yaşı' => '',
        'Alan Adı Kalan Gün' => '',
        'Nameserver' => '',
    ];
    // Basit regexlerle doldur
    preg_match('/Domain Name:\s*(.+)/i', $whois, $m); if (!empty($m[1])) $data['Alan Adı'] = trim($m[1]);
    preg_match('/Registrar:\s*(.+)/i', $whois, $m); if (!empty($m[1])) $data['Kaydedici Firma'] = trim($m[1]);
    preg_match('/Registrar WHOIS Server:\s*(.+)/i', $whois, $m); if (!empty($m[1])) $data['Kaydedici WHOIS'] = trim($m[1]);
    preg_match('/Registrar URL:\s*(.+)/i', $whois, $m); if (!empty($m[1])) $data['Kaydedici URL'] = trim($m[1]);
    preg_match('/Registrar IANA ID:\s*(.+)/i', $whois, $m); if (!empty($m[1])) $data['Kaydedici IANA ID'] = trim($m[1]);
    preg_match('/Abuse Contact Email:\s*(.+)/i', $whois, $m); if (!empty($m[1])) $data['Kötüye Kullanım Mail'] = trim($m[1]);
    preg_match('/Abuse Contact Phone:\s*(.+)/i', $whois, $m); if (!empty($m[1])) $data['Kötüye Kullanım Telefon'] = trim($m[1]);
    preg_match('/Creation Date:\s*(.+)/i', $whois, $m); if (!empty($m[1])) $data['Alan Adı Kayıt Tarihi'] = trim($m[1]);
    preg_match('/Registry Expiry Date:\s*(.+)/i', $whois, $m); if (!empty($m[1])) $data['Alan Adı Bitiş Tarihi'] = trim($m[1]);
    preg_match('/Updated Date:\s*(.+)/i', $whois, $m); if (!empty($m[1])) $data['Alan Adı Güncelleme Tarihi'] = trim($m[1]);
    // Nameserver
    preg_match_all('/Name Server:\s*(.+)/i', $whois, $m); if (!empty($m[1])) $data['Nameserver'] = implode('<br>', $m[1]);
    return $data;
}

function parseRdap($rdap) {
    $data = [
        'Alan Adı' => $rdap['ldhName'] ?? '',
        'Durum' => isset($rdap['status']) ? implode(', ', $rdap['status']) : '',
        'Registrar' => $rdap['registrar']['name'] ?? ($rdap['entities'][0]['vcardArray'][1][1][3] ?? ''),
        'Kayıt Tarihi' => $rdap['events'][0]['eventDate'] ?? '',
        'Bitiş Tarihi' => $rdap['events'][1]['eventDate'] ?? '',
        'Nameserver' => isset($rdap['nameservers']) ? implode('<br>', array_map(function($ns){return $ns['ldhName'];}, $rdap['nameservers'])) : '',
        'İletişim' => '',
    ];
    // İletişim bilgisi
    if (isset($rdap['entities'])) {
        foreach ($rdap['entities'] as $ent) {
            if (isset($ent['vcardArray'][1])) {
                foreach ($ent['vcardArray'][1] as $v) {
                    if ($v[0] === 'email') $data['İletişim'] .= 'E-posta: ' . $v[3] . '<br>';
                    if ($v[0] === 'tel') $data['İletişim'] .= 'Tel: ' . $v[3] . '<br>';
                }
            }
        }
    }
    return $data;
}

function getDomainStatus($dns, $whois = []) {
    $web = !empty($dns['A']);
    $web_ips = [];
    if ($web) {
        foreach ($dns['A'] as $a) {
            if (isset($a['ip'])) $web_ips[] = $a['ip'];
        }
    }
    $mail = !empty($dns['MX']);
    $mx_records = [];
    if ($mail) {
        foreach ($dns['MX'] as $mx) {
            if (isset($mx['target'])) $mx_records[] = $mx['target'] . (isset($mx['pri']) ? ' (Öncelik: ' . $mx['pri'] . ')' : '');
        }
    }
    $ns_records = [];
    if (!empty($dns['NS'])) {
        foreach ($dns['NS'] as $ns) {
            if (isset($ns['target'])) $ns_records[] = $ns['target'];
        }
    }
    $soa_admin = '';
    if (!empty($dns['SOA']) && isset($dns['SOA'][0]['rname'])) {
        $soa_admin = str_replace('.', '@', $dns['SOA'][0]['rname']);
    }
    // Alan adı yaşı ve kalan gün
    $yas = $kalan = '';
    if (!empty($whois['Alan Adı Kayıt Tarihi']) && !empty($whois['Alan Adı Bitiş Tarihi'])) {
        $kayit = strtotime($whois['Alan Adı Kayıt Tarihi']);
        $bitis = strtotime($whois['Alan Adı Bitiş Tarihi']);
        $yas = floor((time() - $kayit) / (365*24*60*60));
        $kalan = floor(($bitis - time()) / (24*60*60));
    }
    return [
        'web' => $web,
        'web_ips' => $web_ips,
        'mail' => $mail,
        'mx_records' => $mx_records,
        'ns_records' => $ns_records,
        'soa_admin' => $soa_admin,
        'yas' => $yas,
        'kalan' => $kalan
    ];
}

$common_subs = [
    'www', 'mail', 'ftp', 'webmail', 'ns1', 'ns2', 'admin', 'shop', 'dev', 'api', 'portal', 'blog', 'test', 'smtp', 'vpn', 'm', 'mobile', 'beta', 'staging', 'support', 'help', 'docs', 'static', 'img', 'cdn', 'download', 'upload', 'files', 'server', 'dns', 'gateway', 'secure', 'dashboard', 'panel', 'cp', 'cpanel', 'webdisk', 'webdav', 'pop', 'pop3', 'imap', 'smtp2', 'relay', 'mail2', 'mail3', 'mail4', 'mx', 'mx1', 'mx2', 'mx3', 'mx4', 'ns3', 'ns4', 'ns5', 'ns6', 'ns7', 'ns8', 'ns9', 'ns10'
];

function getSslInfo($host, $port = 443) {
    $gather = [
        'valid' => false,
        'subject' => '',
        'issuer' => '',
        'validFrom' => '',
        'validTo' => '',
        'daysLeft' => '',
        'error' => ''
    ];
    $host = trim($host);
    if (!$host) return $gather;
    $context = stream_context_create(["ssl" => ["capture_peer_cert" => true, "verify_peer" => false, "verify_peer_name" => false]]);
    $client = @stream_socket_client("ssl://" . $host . ":" . $port, $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $context);
    if (!$client) {
        $gather['error'] = "Bağlantı hatası: $errstr ($errno)";
        return $gather;
    }
    $cont = stream_context_get_params($client);
    if (!isset($cont['options']['ssl']['peer_certificate'])) {
        $gather['error'] = "Sertifika alınamadı.";
        return $gather;
    }
    $cert = openssl_x509_parse($cont['options']['ssl']['peer_certificate']);
    if (!$cert) {
        $gather['error'] = "Sertifika çözümlenemedi.";
        return $gather;
    }
    $gather['subject'] = isset($cert['subject']['CN']) ? $cert['subject']['CN'] : '';
    $gather['issuer'] = isset($cert['issuer']['CN']) ? $cert['issuer']['CN'] : '';
    $gather['validFrom'] = isset($cert['validFrom_time_t']) ? date('Y-m-d H:i:s', $cert['validFrom_time_t']) : '';
    $gather['validTo'] = isset($cert['validTo_time_t']) ? date('Y-m-d H:i:s', $cert['validTo_time_t']) : '';
    if (isset($cert['validTo_time_t'])) {
        $gather['daysLeft'] = floor(($cert['validTo_time_t'] - time()) / 86400);
        $gather['valid'] = ($cert['validTo_time_t'] > time());
    }
    return $gather;
}

function analyzeEmailHeader($header) {
    $score = 0;
    $details = [];
    $header = trim($header);
    $headerLower = strtolower($header);
    $isCertainSpam = false;

    // X-Spam-Flag veya X-Spam-Status kesin spam
    if (preg_match('/x-spam-flag:\s*yes/i', $header) || preg_match('/x-spam-status:\s*yes/i', $header)) {
        $details[] = ['X-Spam-Flag/Status', 'YES', 'Kesin SPAM!'];
        $isCertainSpam = true;
    }
    // X-Spam-Status: NO ise puan ekle
    if (preg_match('/x-spam-status:\s*no/i', $header)) {
        $score += 2;
        $details[] = ['X-Spam-Status', 'NO', '+2'];
    }
    // X-Spam-Level
    if (preg_match('/^X-Spam-Level: (\*+)/mi', $header, $m)) {
        $level = strlen($m[1]);
        $details[] = ['X-Spam-Level', $level, $level > 5 ? '-2' : '+1'];
        if ($level > 5) $score -= 2; else $score += 1;
    }
    // SpamAssassin puanı
    $saScore = null;
    if (preg_match('/X-Spam-Score: ([\d\.\-]+)/i', $header, $m)) {
        $saScore = floatval($m[1]);
        if ($saScore > 3) {
            $details[] = ['SpamAssassin', $saScore, 'Kesin SPAM!'];
            $isCertainSpam = true;
        } elseif ($saScore > 1) {
            $score -= 2;
            $details[] = ['SpamAssassin', $saScore, '-2'];
        } else {
            $score += 1;
            $details[] = ['SpamAssassin', $saScore, '+1'];
        }
    }
    // ARC-Authentication-Results
    if (preg_match('/ARC-Authentication-Results: (.+)/i', $header, $m)) {
        $details[] = ['ARC-Authentication-Results', $m[1], 'Bilgi'];
        if (stripos($m[1], 'fail') !== false) $score -= 2;
    }
    // Authentication-Results
    if (preg_match('/Authentication-Results: (.+)/i', $header, $m)) {
        $details[] = ['Authentication-Results', $m[1], 'Bilgi'];
    }
    // Received-SPF
    if (preg_match('/Received-SPF: (.+)/i', $header, $m)) {
        $details[] = ['Received-SPF', $m[1], 'Bilgi'];
        if (stripos($m[1], 'fail') !== false) {
            $score -= 2;
        }
    }
    // X-SES-Outgoing, X-SES-Outgoing-ID
    if (preg_match('/X-SES-Outgoing/i', $header) || preg_match('/X-SES-Outgoing-ID/i', $header)) {
        $score += 1;
        $details[] = ['Amazon SES', 'Var', '+1'];
    }
    // X-Mailgun-Sending-Ip, X-Mailgun-Sid
    if (preg_match('/X-Mailgun-Sending-Ip:/i', $header) || preg_match('/X-Mailgun-Sid:/i', $header)) {
        $score += 1;
        $details[] = ['Mailgun', 'Var', '+1'];
    }
    // X-SG-EID, X-SG-ID, X-SG-Received
    if (preg_match('/X-SG-EID:/i', $header) || preg_match('/X-SG-ID:/i', $header) || preg_match('/X-SG-Received:/i', $header)) {
        $score += 1;
        $details[] = ['SendGrid', 'Var', '+1'];
    }
    // SPF
    if (stripos($header, 'spf=pass') !== false) {
        $score += 2;
        $details[] = ['SPF', 'Geçti', '+2'];
    } elseif (stripos($header, 'spf=fail') !== false || stripos($header, 'spf=softfail') !== false) {
        $score -= 3;
        $details[] = ['SPF', 'Başarısız', '-3'];
    } else {
        $score -= 1;
        $details[] = ['SPF', 'Bilinmiyor', '-1'];
    }
    // DKIM
    if (stripos($header, 'dkim=pass') !== false) {
        $score += 2;
        $details[] = ['DKIM', 'Geçti', '+2'];
    } elseif (stripos($header, 'dkim=fail') !== false) {
        $score -= 3;
        $details[] = ['DKIM', 'Başarısız', '-3'];
    } else {
        $score -= 1;
        $details[] = ['DKIM', 'Bilinmiyor', '-1'];
    }
    // DMARC
    if (stripos($header, 'dmarc=pass') !== false) {
        $score += 2;
        $details[] = ['DMARC', 'Geçti', '+2'];
    } elseif (stripos($header, 'dmarc=fail') !== false) {
        $score -= 3;
        $details[] = ['DMARC', 'Başarısız', '-3'];
    } else {
        $score -= 1;
        $details[] = ['DMARC', 'Bilinmiyor', '-1'];
    }
    // X-Spam
    if (preg_match('/x-spam.*:.*yes/i', $header)) {
        $score -= 3;
        $details[] = ['X-Spam', 'YES', '-3'];
    } elseif (preg_match('/x-spam.*:.*no/i', $header)) {
        $score += 1;
        $details[] = ['X-Spam', 'NO', '+1'];
    } else {
        $details[] = ['X-Spam', 'Yok', '0'];
    }
    // X-MS-Exchange-Organization-SCL
    if (preg_match('/X-MS-Exchange-Organization-SCL: (\d+)/i', $header, $m)) {
        $scl = intval($m[1]);
        $details[] = ['MS SCL', $scl, $scl >= 5 ? '-2' : '+1'];
        if ($scl >= 5) $score -= 2; else $score += 1;
    }
    // X-Google-Smtp-Source, X-Gm-Message-State
    if (preg_match('/X-Google-Smtp-Source:/i', $header) || preg_match('/X-Gm-Message-State:/i', $header)) {
        $score += 1;
        $details[] = ['Google SMTP', 'Var', '+1'];
    }
    // X-Mailer, X-MimeOLE
    $trustedMailers = ['outlook', 'apple mail', 'gmail', 'thunderbird', 'yahoo', 'hotmail', 'postfix', 'exim', 'phpmailer', 'swiftmailer', 'mailgun', 'sendgrid', 'amazon ses', 'google apps'];
    if (preg_match('/X-Mailer: (.+)/i', $header, $m)) {
        $mailer = strtolower($m[1]);
        $isTrusted = false;
        foreach ($trustedMailers as $trusted) {
            if (strpos($mailer, $trusted) !== false) $isTrusted = true;
        }
        if ($isTrusted) {
            $score += 2;
            $details[] = ['X-Mailer', $mailer, '+2'];
        } else {
            $score -= 1;
            $details[] = ['X-Mailer', $mailer, '-1'];
        }
    } else {
        $score -= 1;
        $details[] = ['X-Mailer', 'Yok', '-1'];
    }
    if (preg_match('/X-MimeOLE: (.+)/i', $header, $m)) {
        $details[] = ['X-MimeOLE', $m[1], 'Bilgi'];
    }
    // X-Originating-Email
    if (preg_match('/X-Originating-Email: (.+)/i', $header, $m)) {
        $email = trim($m[1]);
        $details[] = ['X-Originating-Email', $email, 'Bilgi'];
        if (preg_match('/@(gmail|yahoo|hotmail|outlook|mail|protonmail|icloud|aol|yandex|zoho)\./i', $email)) {
            $score += 1;
            $details[] = ['X-Originating-Email', 'Güvenilir domain', '+1'];
        } else {
            $score -= 1;
            $details[] = ['X-Originating-Email', 'Özel domain', '-1'];
        }
    }
    // X-Get-Message-Sender-Via
    if (preg_match('/X-Get-Message-Sender-Via: (.+)/i', $header, $m)) {
        $details[] = ['X-Get-Message-Sender-Via', $m[1], 'Bilgi'];
    }
    // X-Envelope-Sender
    if (preg_match('/X-Envelope-Sender: (.+)/i', $header, $m)) {
        $details[] = ['X-Envelope-Sender', $m[1], 'Bilgi'];
    }
    // X-Return-Path
    if (preg_match('/X-Return-Path: (.+)/i', $header, $m)) {
        $details[] = ['X-Return-Path', $m[1], 'Bilgi'];
    }
    // X-Feedback-ID
    if (preg_match('/X-Feedback-ID: (.+)/i', $header, $m)) {
        $details[] = ['X-Feedback-ID', $m[1], 'Bilgi'];
    }
    // X-Report-Abuse-To
    if (preg_match('/X-Report-Abuse-To: (.+)/i', $header, $m)) {
        $details[] = ['X-Report-Abuse-To', $m[1], 'Bilgi'];
    }
    // Return-Path
    $returnPath = null;
    if (preg_match('/^Return-Path:.*<(.*)>/mi', $header, $m)) {
        $returnPath = trim($m[1]);
        $score += 1;
        $details[] = ['Return-Path', $returnPath, '+1'];
    } else {
        $score -= 2;
        $details[] = ['Return-Path', 'Yok', '-2'];
    }
    // Envelope-From
    $envelopeFrom = null;
    if (preg_match('/^X-Envelope-From:.*<(.*)>/mi', $header, $m)) {
        $envelopeFrom = trim($m[1]);
        $details[] = ['Envelope-From', $envelopeFrom, 'Bilgi'];
    }
    // Envelope-To
    if (preg_match('/^X-Envelope-To:.*<(.*)>/mi', $header, $m)) {
        $details[] = ['Envelope-To', trim($m[1]), 'Bilgi'];
    }
    // X-Original-To, Delivered-To
    if (preg_match('/^X-Original-To: (.*)/mi', $header, $m)) {
        $details[] = ['X-Original-To', trim($m[1]), 'Bilgi'];
    }
    if (preg_match('/^Delivered-To: (.*)/mi', $header, $m)) {
        $details[] = ['Delivered-To', trim($m[1]), 'Bilgi'];
    }
    // X-Original-From, X-Original-Message-ID, X-Original-Sender, X-Original-Authentication-Results, X-Original-Recipient, X-Original-Arrival-Time, X-Original-Envelope-Id, X-Original-Return-Path, X-Original-To, X-Original-Delivered-To, X-Original-Received, X-Original-Subject, X-Original-Date
    $originalHeaders = [
        'X-Original-From', 'X-Original-Message-ID', 'X-Original-Sender', 'X-Original-Authentication-Results',
        'X-Original-Recipient', 'X-Original-Arrival-Time', 'X-Original-Envelope-Id', 'X-Original-Return-Path',
        'X-Original-To', 'X-Original-Delivered-To', 'X-Original-Received', 'X-Original-Subject', 'X-Original-Date'
    ];
    foreach ($originalHeaders as $oh) {
        if (preg_match('/^' . preg_quote($oh, '/') . ':(.*)/mi', $header, $m)) {
            $details[] = [$oh, trim($m[1]), 'Bilgi'];
        }
    }
    // Reply-To
    $replyTo = null;
    if (preg_match('/^Reply-To:.*<(.*)>/mi', $header, $m)) {
        $replyTo = trim($m[1]);
        $score += 1;
        $details[] = ['Reply-To', $replyTo, '+1'];
    } else {
        $details[] = ['Reply-To', 'Yok', '0'];
    }
    // From
    $from = null;
    if (preg_match('/^From:.*<(.*)>/mi', $header, $m)) {
        $from = trim($m[1]);
        $score += 1;
        $details[] = ['From', $from, '+1'];
    } else {
        $score -= 2;
        $details[] = ['From', 'Yok', '-2'];
    }
    // Return-Path ile From farklıysa
    if ($returnPath && $from && strtolower($returnPath) !== strtolower($from)) {
        $score -= 2;
        $details[] = ['Return-Path ≠ From', 'Farklı', '-2'];
    }
    // Envelope-From ile From farklıysa
    if ($envelopeFrom && $from && strtolower($envelopeFrom) !== strtolower($from)) {
        $score -= 2;
        $details[] = ['Envelope-From ≠ From', 'Farklı', '-2'];
    }
    // Message-ID
    if (preg_match('/^Message-ID:/mi', $header)) {
        $score += 1;
        $details[] = ['Message-ID', 'Var', '+1'];
    } else {
        $score -= 2;
        $details[] = ['Message-ID', 'Yok', '-2'];
    }
    // User-Agent/Mailer
    if (preg_match('/(User-Agent|X-Mailer):/i', $header)) {
        $score += 1;
        $details[] = ['User-Agent/X-Mailer', 'Var', '+1'];
    } else {
        $score -= 1;
        $details[] = ['User-Agent/X-Mailer', 'Yok', '-1'];
    }
    // Received zinciri
    $receivedCount = preg_match_all('/^Received:/mi', $header, $rcv);
    if ($receivedCount > 1 && $receivedCount <= 10) {
        $score += 1;
        $details[] = ['Received', $receivedCount . ' adet', '+1'];
    } elseif ($receivedCount > 10) {
        $score -= 2;
        $details[] = ['Received', $receivedCount . ' (Çok fazla)', '-2'];
    } else {
        $score -= 2;
        $details[] = ['Received', 'Yetersiz', '-2'];
    }
    // X-Originating-IP
    if (preg_match('/X-Originating-IP: \[([\d\.]+)\]/i', $header, $m)) {
        $ip = $m[1];
        $details[] = ['X-Originating-IP', $ip, 'Bilgi'];
        if (preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/', $ip)) {
            $score -= 1;
            $details[] = ['X-Originating-IP', 'Özel IP', '-1'];
        }
    }
    // X-Forwarded-For
    if (preg_match('/X-Forwarded-For: ([^\s]+)/i', $header, $m)) {
        $details[] = ['X-Forwarded-For', $m[1], 'Bilgi'];
    }
    // base64 encoded subject veya From
    if (preg_match('/^Subject: =\?utf-8\?b\?/mi', $header) || preg_match('/^From: =\?utf-8\?b\?/mi', $header)) {
        $score -= 2;
        $details[] = ['Base64 Subject/From', 'Var', '-2'];
    }
    // Content-Type
    if (preg_match('/^Content-Type: (.+)/mi', $header, $m)) {
        $ct = strtolower($m[1]);
        $details[] = ['Content-Type', $ct, 'Bilgi'];
        if (strpos($ct, 'text/html') !== false && strpos($ct, 'multipart') === false) {
            $score -= 1;
            $details[] = ['Content-Type', 'Sadece HTML', '-1'];
        } elseif (strpos($ct, 'multipart') !== false) {
            $score += 1;
            $details[] = ['Content-Type', 'Multipart', '+1'];
        }
    }
    // MIME-Version
    if (preg_match('/^MIME-Version:/mi', $header)) {
        $score += 1;
        $details[] = ['MIME-Version', 'Var', '+1'];
    } else {
        $score -= 1;
        $details[] = ['MIME-Version', 'Yok', '-1'];
    }
    // List-Unsubscribe
    if (preg_match('/^List-Unsubscribe:/mi', $header)) {
        $score += 1;
        $details[] = ['List-Unsubscribe', 'Var', '+1'];
    }
    // X-List-Unsubscribe
    if (preg_match('/^X-List-Unsubscribe:/mi', $header)) {
        $score += 1;
        $details[] = ['X-List-Unsubscribe', 'Var', '+1'];
    }
    // Precedence: bulk/junk
    if (preg_match('/^Precedence: (bulk|junk)/mi', $header, $m)) {
        $score -= 2;
        $details[] = ['Precedence', $m[1], '-2'];
    }
    // X-Precedence: bulk/junk
    if (preg_match('/^X-Precedence: (bulk|junk)/mi', $header, $m)) {
        $score -= 2;
        $details[] = ['X-Precedence', $m[1], '-2'];
    }
    // X-Spam-Report
    if (preg_match('/^X-Spam-Report:(.*)/mi', $header, $m)) {
        $details[] = ['X-Spam-Report', trim($m[1]), 'Bilgi'];
    }
    // X-AntiAbuse, X-Antivirus, X-Spam-Checker-Version
    if (preg_match('/^X-AntiAbuse:(.*)/mi', $header, $m)) {
        $details[] = ['X-AntiAbuse', trim($m[1]), 'Bilgi'];
    }
    if (preg_match('/^X-Antivirus:(.*)/mi', $header, $m)) {
        $details[] = ['X-Antivirus', trim($m[1]), 'Bilgi'];
    }
    if (preg_match('/^X-Spam-Checker-Version:(.*)/mi', $header, $m)) {
        $details[] = ['X-Spam-Checker-Version', trim($m[1]), 'Bilgi'];
    }
    // Sonuç
    $isSpam = $isCertainSpam || $score < 1;
    return [
        'score' => $score,
        'isSpam' => $isSpam,
        'details' => $details
    ];
}

// IP/ASN Bilgisi için yardımcı fonksiyon
function getIpAsnInfo($ip) {
    $url = "https://ipinfo.io/" . urlencode($ip) . "/json";
    $response = @file_get_contents($url);
    if ($response === false) return [];
    $data = json_decode($response, true);
    return $data;
}

// Blacklist kontrolü için yardımcı fonksiyon
function checkBlacklist($ipOrDomain) {
    $blacklists = [
        'zen.spamhaus.org',
        'bl.spamcop.net',
        'b.barracudacentral.org',
        'dnsbl.sorbs.net',
        'psbl.surriel.com',
        'spamrbl.imp.ch',
        'ubl.unsubscore.com',
        'dnsbl-1.uceprotect.net',
        'dnsbl-2.uceprotect.net',
        'dnsbl-3.uceprotect.net',
    ];
    // Eğer domain ise IP'ye çevir
    if (filter_var($ipOrDomain, FILTER_VALIDATE_IP)) {
        $ip = $ipOrDomain;
    } else {
        $ip = gethostbyname($ipOrDomain);
        if ($ip === $ipOrDomain) return [];
    }
    $results = [];
    $rev = implode('.', array_reverse(explode('.', $ip)));
    foreach ($blacklists as $bl) {
        $lookup = $rev . "." . $bl;
        $listed = gethostbyname($lookup) !== $lookup;
        $results[] = [
            'bl' => $bl,
            'listed' => $listed
        ];
    }
    return $results;
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>DNS, NSLOOKUP, WHOIS, Subdomain & SSL Sorgu Aracı</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #f8fafc 0%, #e9ecef 100%);
            font-family: 'Inter', Arial, sans-serif;
        }
        .main-title {
            font-size: 2.5rem;
            font-weight: 700;
            letter-spacing: 1px;
            margin-bottom: 2.7rem;
            color: #1a1a2e;
            text-align: center;
            text-shadow: 0 2px 8px #e9ecef;
        }
        .main-title i {
            color: #6366f1;
            margin-right: 14px;
        }
        .modern-card {
            border-radius: 1.5rem;
            box-shadow: 0 8px 32px 0 rgba(34,34,59,0.13);
            border: none;
            background: #fff;
            transition: box-shadow 0.2s, transform 0.2s;
            margin-bottom: 2.5rem;
        }
        .modern-card:hover {
            box-shadow: 0 16px 48px 0 rgba(99,102,241,0.13);
            transform: translateY(-4px) scale(1.01);
        }
        .modern-header {
            font-size: 1.22rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.7rem;
            border-radius: 1.5rem 1.5rem 0 0;
            background: linear-gradient(90deg, #6366f1 0%, #60a5fa 100%);
            color: #fff;
            border-bottom: 1px solid #e9ecef;
            padding: 1.1rem 1.5rem;
        }
        .table-sm td, .table-sm th {
            font-size: 1.13rem;
            vertical-align: middle;
            padding: 0.7rem 0.8rem;
        }
        .input-group .form-control, .input-group .form-select {
            font-size: 1.18rem;
            border-radius: 2rem 0 0 2rem !important;
            box-shadow: 0 2px 8px 0 rgba(34,34,59,0.04);
            border: 1.5px solid #e0e7ff;
            padding: 1.1rem 1.3rem;
            background: #f8fafc;
        }
        .input-group .form-select {
            border-radius: 0 !important;
        }
        .input-group .btn {
            font-size: 1.18rem;
            border-radius: 0 2rem 2rem 0 !important;
            padding-left: 2.2rem;
            padding-right: 2.2rem;
            font-weight: 700;
            box-shadow: 0 2px 8px 0 rgba(99,102,241,0.08);
            transition: background 0.2s, color 0.2s, box-shadow 0.2s;
        }
        .input-group .btn:focus, .input-group .btn:hover {
            background: linear-gradient(90deg, #6366f1 0%, #60a5fa 100%);
            color: #fff;
            box-shadow: 0 4px 16px 0 rgba(99,102,241,0.13);
        }
        .nav-tabs {
            border-bottom: none;
            margin-bottom: 2.7rem;
            gap: 0.5rem;
        }
        .nav-tabs .nav-link {
            border: none;
            border-radius: 2rem 2rem 0 0;
            background: #f1f5f9;
            color: #495057;
            font-weight: 700;
            font-size: 1.13rem;
            padding: 1.1rem 2.5rem;
            margin-right: 0.5rem;
            transition: background 0.2s, color 0.2s, box-shadow 0.2s;
        }
        .nav-tabs .nav-link.active {
            background: linear-gradient(90deg, #6366f1 0%, #60a5fa 100%);
            color: #fff;
            box-shadow: 0 4px 16px 0 rgba(99,102,241,0.13);
        }
        .nav-tabs .nav-link:hover, .nav-tabs .nav-link:focus {
            background: #e0e7ff;
            color: #1a1a2e;
        }
        pre.whois-raw {
            background: #f8fafc;
            border-radius: 0.9rem;
            padding: 1.3rem;
            font-size: 1.08rem;
            color: #333;
            border: 1.5px solid #e0e7ff;
        }
        .list-group-item {
            background: transparent;
            border: none;
            font-size: 1.13rem;
        }
        .alert {
            border-radius: 1.1rem;
            font-size: 1.13rem;
            padding: 1.1rem 1.3rem;
        }
        .badge {
            font-size: 1.01rem;
            border-radius: 0.7rem;
            padding: 0.5em 1em;
        }
        .fade {
            transition: opacity 0.3s linear;
        }
        @media (max-width: 767px) {
            .main-title { font-size: 1.3rem; }
            .modern-header { font-size: 1rem; }
            .nav-tabs .nav-link { font-size: 0.98rem; padding: 0.7rem 1.1rem; }
            .input-group .form-control, .input-group .form-select { font-size: 1rem; padding: 0.7rem 0.8rem; }
        }
    </style>
</head>
<body>
<div class="container py-5">
    <div class="main-title mb-4">
        <i class="bi bi-diagram-3"></i> DNS, NSLOOKUP, WHOIS, Subdomain & SSL Sorgu Aracı
    </div>
    <ul class="nav nav-tabs mb-4" id="myTab" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link <?=(empty($_POST['tab']) || $_POST['tab']==='dns') ? 'active' : ''?>" id="dns-tab" data-bs-toggle="tab" data-bs-target="#dns" type="button" role="tab" aria-controls="dns" aria-selected="true">DNS Kayıtları</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link <?=(!empty($_POST['tab']) && $_POST['tab']==='nslookup') ? 'active' : ''?>" id="nslookup-tab" data-bs-toggle="tab" data-bs-target="#nslookup" type="button" role="tab" aria-controls="nslookup" aria-selected="false">NSLOOKUP</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link <?=(!empty($_POST['tab']) && $_POST['tab']==='whois') ? 'active' : ''?>" id="whois-tab" data-bs-toggle="tab" data-bs-target="#whois" type="button" role="tab" aria-controls="whois" aria-selected="false">WHOIS Sorgu</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link <?=(!empty($_POST['tab']) && $_POST['tab']==='subdomain') ? 'active' : ''?>" id="subdomain-tab" data-bs-toggle="tab" data-bs-target="#subdomain" type="button" role="tab" aria-controls="subdomain" aria-selected="false">Subdomain Tespit</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link <?=(!empty($_POST['tab']) && $_POST['tab']==='ssl') ? 'active' : ''?>" id="ssl-tab" data-bs-toggle="tab" data-bs-target="#ssl" type="button" role="tab" aria-controls="ssl" aria-selected="false">SSL Sorgu</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link <?=(!empty($_POST['tab']) && $_POST['tab']==='emailheader') ? 'active' : ''?>" id="emailheader-tab" data-bs-toggle="tab" data-bs-target="#emailheader" type="button" role="tab" aria-controls="emailheader" aria-selected="false">E-Posta Header Analiz</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link <?=(!empty($_POST['tab']) && $_POST['tab']==='ipinfo') ? 'active' : ''?>" id="ipinfo-tab" data-bs-toggle="tab" data-bs-target="#ipinfo" type="button" role="tab" aria-controls="ipinfo" aria-selected="false">IP/ASN Bilgisi</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link <?=(!empty($_POST['tab']) && $_POST['tab']==='blacklist') ? 'active' : ''?>" id="blacklist-tab" data-bs-toggle="tab" data-bs-target="#blacklist" type="button" role="tab" aria-controls="blacklist" aria-selected="false">Blacklist Kontrolü</button>
        </li>
    </ul>
    <div class="tab-content" id="myTabContent">
        <!-- DNS Kayıtları Sekmesi -->
        <div class="tab-pane fade <?=(empty($_POST['tab']) || $_POST['tab']==='dns') ? 'show active' : ''?>" id="dns" role="tabpanel" aria-labelledby="dns-tab">
            <form method="post" class="mb-5">
                <input type="hidden" name="tab" value="dns">
                <div class="input-group justify-content-center">
                    <input type="text" name="domain" class="form-control w-50" placeholder="ornek.com" required value="<?=isset($_POST['tab']) && $_POST['tab']==='dns' ? htmlspecialchars($_POST['domain'] ?? '') : ''?>">
                    <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Sorgula</button>
                </div>
            </form>
            <?php if ($_SERVER['REQUEST_METHOD'] === 'POST' && (!isset($_POST['tab']) || $_POST['tab']==='dns') && !empty($_POST['domain'])): 
                $domain = trim($_POST['domain']);
                $dns = getDnsRecords($domain);
            ?>
            <div class="row g-4">
                <div class="col-md-10 offset-md-1">
                    <div class="modern-card">
                        <div class="modern-header bg-success text-white">
                            <i class="bi bi-diagram-3"></i> Tüm DNS Kayıtları
                        </div>
                        <div class="card-body p-0">
                            <table class="table table-sm mb-0">
                                <thead><tr><th>KAYIT TÜRÜ</th><th>DEĞER</th></tr></thead>
                                <tbody>
                                <?php foreach ($dns as $type => $records): ?>
                                    <?php foreach ($records as $rec): ?>
                                        <tr>
                                            <td><?=htmlspecialchars($type)?></td>
                                            <td>
                                                <?php
                                                if ($type == 'A' && isset($rec['ip'])) echo htmlspecialchars($rec['ip']);
                                                elseif ($type == 'CNAME' && isset($rec['target'])) echo htmlspecialchars($rec['target']);
                                                elseif ($type == 'NS' && isset($rec['target'])) echo htmlspecialchars($rec['target']);
                                                elseif ($type == 'MX' && isset($rec['target'])) echo htmlspecialchars($rec['target']) . ' ('.htmlspecialchars($rec['pri']).')';
                                                elseif ($type == 'SOA') echo htmlspecialchars($rec['rname'] ?? '');
                                                elseif ($type == 'TXT' && isset($rec['txt'])) echo htmlspecialchars($rec['txt']);
                                                else echo htmlspecialchars(json_encode($rec));
                                                ?>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            <?php endif; ?>
        </div>
        <!-- NSLOOKUP Sekmesi -->
        <div class="tab-pane fade <?=(!empty($_POST['tab']) && $_POST['tab']==='nslookup') ? 'show active' : ''?>" id="nslookup" role="tabpanel" aria-labelledby="nslookup-tab">
            <form method="post" class="mb-5">
                <input type="hidden" name="tab" value="nslookup">
                <div class="row justify-content-center g-2">
                    <div class="col-md-5 col-12">
                        <input type="text" name="domain" class="form-control" placeholder="ornek.com" required value="<?=isset($_POST['tab']) && $_POST['tab']==='nslookup' ? htmlspecialchars($_POST['domain'] ?? '') : ''?>">
                    </div>
                    <div class="col-md-3 col-8">
                        <select name="record_type" class="form-select" required>
                            <option value="A" <?=isset($_POST['record_type']) && $_POST['record_type']==='A' ? 'selected' : ''?>>A</option>
                            <option value="MX" <?=isset($_POST['record_type']) && $_POST['record_type']==='MX' ? 'selected' : ''?>>MX</option>
                            <option value="NS" <?=isset($_POST['record_type']) && $_POST['record_type']==='NS' ? 'selected' : ''?>>NS</option>
                            <option value="TXT" <?=isset($_POST['record_type']) && $_POST['record_type']==='TXT' ? 'selected' : ''?>>TXT</option>
                            <option value="CNAME" <?=isset($_POST['record_type']) && $_POST['record_type']==='CNAME' ? 'selected' : ''?>>CNAME</option>
                            <option value="SOA" <?=isset($_POST['record_type']) && $_POST['record_type']==='SOA' ? 'selected' : ''?>>SOA</option>
                        </select>
                    </div>
                    <div class="col-md-2 col-4">
                        <button class="btn btn-primary w-100" type="submit"><i class="bi bi-search"></i> Sorgula</button>
                    </div>
                </div>
            </form>
            <?php if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['tab']) && $_POST['tab']==='nslookup' && !empty($_POST['domain']) && !empty($_POST['record_type'])): 
                $domain = trim($_POST['domain']);
                $type = strtoupper(trim($_POST['record_type']));
                $dns = @dns_get_record($domain, constant('DNS_' . $type));
            ?>
            <div class="row g-4">
                <div class="col-md-10 offset-md-1">
                    <div class="modern-card">
                        <div class="modern-header bg-success text-white">
                            <i class="bi bi-diagram-3"></i> NSLOOKUP Sonucu (<?=$type?> Kaydı)
                        </div>
                        <div class="card-body p-0">
                            <?php if (empty($dns)): ?>
                                <div class="alert alert-warning m-3">Kayıt bulunamadı veya sorgu başarısız oldu.</div>
                            <?php else: ?>
                            <table class="table table-sm mb-0">
                                <thead><tr>
                                    <?php foreach (array_keys($dns[0]) as $col): ?>
                                        <th><?=htmlspecialchars($col)?></th>
                                    <?php endforeach; ?>
                                </tr></thead>
                                <tbody>
                                <?php foreach ($dns as $rec): ?>
                                    <tr>
                                        <?php foreach ($rec as $v): ?>
                                            <td><?=htmlspecialchars(is_array($v) ? json_encode($v) : $v)?></td>
                                        <?php endforeach; ?>
                                    </tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
            <?php endif; ?>
        </div>
        <!-- WHOIS Sekmesi -->
        <div class="tab-pane fade <?=(!empty($_POST['tab']) && $_POST['tab']==='whois') ? 'show active' : ''?>" id="whois" role="tabpanel" aria-labelledby="whois-tab">
            <form method="post" class="mb-5">
                <input type="hidden" name="tab" value="whois">
                <div class="input-group justify-content-center">
                    <input type="text" name="domain" class="form-control w-50" placeholder="ornek.com" required value="<?=isset($_POST['tab']) && $_POST['tab']==='whois' ? htmlspecialchars($_POST['domain'] ?? '') : ''?>">
                    <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Sorgula</button>
                </div>
            </form>
            <?php if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['tab']) && $_POST['tab']==='whois' && !empty($_POST['domain'])): 
                $domain = trim($_POST['domain']);
                $whois_raw = getWhois($domain);
            ?>
            <div class="row g-4">
                <div class="col-md-10 offset-md-1">
                    <div class="modern-card">
                        <div class="modern-header bg-info text-white">
                            <i class="bi bi-person-badge"></i> WHOIS Sonucu
                        </div>
                        <div class="card-body">
                            <?php if (empty(trim($whois_raw))): ?>
                                <div class="alert alert-warning">WHOIS bilgisi alınamadı veya API limiti dolmuş olabilir.</div>
                            <?php else: ?>
                                <pre class="whois-raw"><?=htmlspecialchars($whois_raw)?></pre>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
            <?php endif; ?>
        </div>
        <!-- Subdomain Tespit Sekmesi -->
        <div class="tab-pane fade <?=(!empty($_POST['tab']) && $_POST['tab']==='subdomain') ? 'show active' : ''?>" id="subdomain" role="tabpanel" aria-labelledby="subdomain-tab">
            <form method="post" class="mb-5">
                <input type="hidden" name="tab" value="subdomain">
                <div class="input-group justify-content-center">
                    <input type="text" name="domain" class="form-control w-50" placeholder="ornek.com" required value="<?=isset($_POST['tab']) && $_POST['tab']==='subdomain' ? htmlspecialchars($_POST['domain'] ?? '') : ''?>">
                    <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Tespit Et</button>
                </div>
            </form>
            <?php
            $results = [];
            if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['tab']) && $_POST['tab']==='subdomain' && !empty($_POST['domain'])) {
                $domain = trim($_POST['domain']);
                foreach ($common_subs as $sub) {
                    $fqdn = $sub . '.' . $domain;
                    $a = @dns_get_record($fqdn, DNS_A);
                    if (!empty($a)) {
                        $results[] = [
                            'subdomain' => $fqdn,
                            'ip' => isset($a[0]['ip']) ? $a[0]['ip'] : '-',
                        ];
                    }
                }
            }
            ?>
            <?php if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['tab']) && $_POST['tab']==='subdomain' && !empty($_POST['domain'])): ?>
            <div class="row g-4">
                <div class="col-md-10 offset-md-1">
                    <div class="modern-card">
                        <div class="modern-header bg-info text-white">
                            <i class="bi bi-diagram-3"></i> Bulunan Subdomainler
                        </div>
                        <div class="card-body p-0">
                            <?php if (empty($results)): ?>
                                <div class="alert alert-warning m-3">Hiçbir yaygın subdomain bulunamadı.</div>
                            <?php else: ?>
                            <table class="table table-sm mb-0">
                                <thead><tr><th>Subdomain</th><th>IP Adresi</th></tr></thead>
                                <tbody>
                                <?php foreach ($results as $row): ?>
                                    <tr>
                                        <td><?=htmlspecialchars($row['subdomain'])?></td>
                                        <td><?=htmlspecialchars($row['ip'])?></td>
                                    </tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
            <?php endif; ?>
        </div>
        <!-- SSL Sorgu Sekmesi -->
        <div class="tab-pane fade <?=(!empty($_POST['tab']) && $_POST['tab']==='ssl') ? 'show active' : ''?>" id="ssl" role="tabpanel" aria-labelledby="ssl-tab">
            <form method="post" class="mb-5">
                <input type="hidden" name="tab" value="ssl">
                <div class="input-group justify-content-center">
                    <input type="text" name="domain" class="form-control w-50" placeholder="ornek.com veya ornek.com:443" required value="<?=isset($_POST['tab']) && $_POST['tab']==='ssl' ? htmlspecialchars($_POST['domain'] ?? '') : ''?>">
                    <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Sorgula</button>
                </div>
            </form>
            <?php
            $ssl = null;
            if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['tab']) && $_POST['tab']==='ssl' && !empty($_POST['domain'])) {
                $input = trim($_POST['domain']);
                $parts = explode(':', $input);
                $host = $parts[0];
                $port = isset($parts[1]) ? (int)$parts[1] : 443;
                $ssl = getSslInfo($host, $port);
            }
            ?>
            <?php if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['tab']) && $_POST['tab']==='ssl' && !empty($_POST['domain'])): ?>
            <div class="row g-4">
                <div class="col-md-10 offset-md-1">
                    <div class="modern-card">
                        <div class="modern-header bg-warning text-dark">
                            <i class="bi bi-lock"></i> SSL Sertifika Bilgisi
                        </div>
                        <div class="card-body">
                            <?php if (!$ssl || $ssl['error']): ?>
                                <div class="alert alert-danger">SSL sorgusu başarısız: <?=htmlspecialchars($ssl['error'])?></div>
                            <?php else: ?>
                                <ul class="list-group list-group-flush mb-3">
                                    <li class="list-group-item"><b>Alan Adı (Subject):</b> <?=htmlspecialchars($ssl['subject'])?></li>
                                    <li class="list-group-item"><b>Veren (Issuer):</b> <?=htmlspecialchars($ssl['issuer'])?></li>
                                    <li class="list-group-item"><b>Geçerlilik Başlangıcı:</b> <?=htmlspecialchars($ssl['validFrom'])?></li>
                                    <li class="list-group-item"><b>Geçerlilik Bitişi:</b> <?=htmlspecialchars($ssl['validTo'])?></li>
                                    <li class="list-group-item"><b>Kalan Gün:</b> <?=htmlspecialchars($ssl['daysLeft'])?></li>
                                    <li class="list-group-item"><b>Geçerli mi?:</b> <?=($ssl['valid'] ? '<span class="text-success">Evet</span>' : '<span class="text-danger">Hayır</span>')?></li>
                                </ul>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
            <?php endif; ?>
        </div>
        <!-- E-Posta Header Analiz Sekmesi -->
        <div class="tab-pane fade <?=(!empty($_POST['tab']) && $_POST['tab']==='emailheader') ? 'show active' : ''?>" id="emailheader" role="tabpanel" aria-labelledby="emailheader-tab">
            <form method="post" class="mb-5">
                <input type="hidden" name="tab" value="emailheader">
                <div class="mb-3 row justify-content-center">
                    <div class="col-md-8 col-12">
                        <textarea name="header" class="form-control form-control-lg rounded-4 shadow-sm" rows="10" placeholder="E-posta header'ını buraya yapıştırın..." required><?=isset($_POST['tab']) && $_POST['tab']==='emailheader' ? htmlspecialchars($_POST['header'] ?? '') : ''?></textarea>
                    </div>
                </div>
                <div class="row justify-content-center">
                    <div class="col-md-3 col-6">
                        <button class="btn btn-primary btn-lg w-100 rounded-pill" type="submit"><i class="bi bi-search"></i> Analiz Et</button>
                    </div>
                </div>
            </form>
            <?php
            $headerResult = null;
            if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['tab']) && $_POST['tab']==='emailheader' && !empty($_POST['header'])) {
                $headerResult = analyzeEmailHeader($_POST['header']);
            }
            ?>
            <?php if ($headerResult): ?>
            <div class="row g-4">
                <div class="col-md-8 offset-md-2">
                    <div class="modern-card">
                        <div class="modern-header bg-gradient" style="background: linear-gradient(90deg, #f59e42 0%, #f43f5e 100%); color: #fff;">
                            <i class="bi bi-envelope-exclamation"></i> Analiz Sonucu
                        </div>
                        <div class="card-body">
                            <div class="mb-3">
                                <span class="badge <?= $headerResult['isSpam'] ? 'bg-danger' : 'bg-success' ?> fs-5 px-4 py-2">
                                    <?= $headerResult['isSpam'] ? 'SPAM' : 'SPAM DEĞİL' ?>
                                </span>
                                <span class="ms-3">Puan: <b><?= $headerResult['score'] ?></b></span>
                            </div>
                            <table class="table table-sm table-bordered mb-0">
                                <thead class="table-light"><tr><th>Özellik</th><th>Durum</th><th>Puan</th></tr></thead>
                                <tbody>
                                <?php foreach ($headerResult['details'] as $row): ?>
                                    <tr>
                                        <td><?=htmlspecialchars($row[0])?></td>
                                        <td><?=htmlspecialchars($row[1])?></td>
                                        <td><?=htmlspecialchars($row[2])?></td>
                                    </tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            <?php endif; ?>
        </div>
        <!-- IP/ASN Bilgisi Sekmesi -->
        <div class="tab-pane fade <?=(!empty($_POST['tab']) && $_POST['tab']==='ipinfo') ? 'show active' : ''?>" id="ipinfo" role="tabpanel" aria-labelledby="ipinfo-tab">
            <form method="post" class="mb-5">
                <input type="hidden" name="tab" value="ipinfo">
                <div class="input-group justify-content-center">
                    <input type="text" name="ip" class="form-control w-50" placeholder="IP adresi veya domain" required value="<?=isset($_POST['tab']) && $_POST['tab']==='ipinfo' ? htmlspecialchars($_POST['ip'] ?? '') : ''?>">
                    <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Sorgula</button>
                </div>
            </form>
            <?php if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['tab']) && $_POST['tab']==='ipinfo' && !empty($_POST['ip'])): 
                $ip = trim($_POST['ip']);
                $info = getIpAsnInfo($ip);
            ?>
            <div class="row g-4">
                <div class="col-md-10 offset-md-1">
                    <div class="modern-card">
                        <div class="modern-header bg-primary text-white">
                            <i class="bi bi-info-circle"></i> IP/ASN Bilgisi
                        </div>
                        <div class="card-body">
                            <?php if (empty($info)): ?>
                                <div class="alert alert-warning">Bilgi alınamadı.</div>
                            <?php else: ?>
                                <ul class="list-group list-group-flush mb-3">
                                    <li class="list-group-item"><b>IP:</b> <?=htmlspecialchars($info['ip'] ?? '')?></li>
                                    <li class="list-group-item"><b>Hostname:</b> <?=htmlspecialchars($info['hostname'] ?? '-')?></li>
                                    <li class="list-group-item"><b>Ülke:</b> <?=htmlspecialchars($info['country'] ?? '-')?></li>
                                    <li class="list-group-item"><b>Şehir:</b> <?=htmlspecialchars($info['city'] ?? '-')?></li>
                                    <li class="list-group-item"><b>Org/ASN:</b> <?=htmlspecialchars($info['org'] ?? '-')?></li>
                                    <li class="list-group-item"><b>ISP:</b> <?=htmlspecialchars($info['org'] ?? '-')?></li>
                                </ul>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
            <?php endif; ?>
        </div>
        <!-- Blacklist Kontrolü Sekmesi -->
        <div class="tab-pane fade <?=(!empty($_POST['tab']) && $_POST['tab']==='blacklist') ? 'show active' : ''?>" id="blacklist" role="tabpanel" aria-labelledby="blacklist-tab">
            <form method="post" class="mb-5">
                <input type="hidden" name="tab" value="blacklist">
                <div class="input-group justify-content-center">
                    <input type="text" name="ip" class="form-control w-50" placeholder="IP adresi veya domain" required value="<?=isset($_POST['tab']) && $_POST['tab']==='blacklist' ? htmlspecialchars($_POST['ip'] ?? '') : ''?>">
                    <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Kontrol Et</button>
                </div>
            </form>
            <?php if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['tab']) && $_POST['tab']==='blacklist' && !empty($_POST['ip'])): 
                $ip = trim($_POST['ip']);
                $results = checkBlacklist($ip);
            ?>
            <div class="row g-4">
                <div class="col-md-10 offset-md-1">
                    <div class="modern-card">
                        <div class="modern-header bg-danger text-white">
                            <i class="bi bi-shield-exclamation"></i> Blacklist Sonucu
                        </div>
                        <div class="card-body">
                            <?php if (empty($results)): ?>
                                <div class="alert alert-warning">IP veya domain çözümlenemedi ya da bilgi alınamadı.</div>
                            <?php else: ?>
                                <table class="table table-sm table-bordered mb-0">
                                    <thead class="table-light"><tr><th>Blacklist</th><th>Durum</th></tr></thead>
                                    <tbody>
                                    <?php foreach ($results as $row): ?>
                                        <tr>
                                            <td><?=htmlspecialchars($row['bl'])?></td>
                                            <td><?=($row['listed'] ? '<span class="badge bg-danger">Listede</span>' : '<span class="badge bg-success">Temiz</span>')?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                    </tbody>
                                </table>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
            <?php endif; ?>
        </div>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 