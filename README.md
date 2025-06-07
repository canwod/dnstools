DNS, NSLOOKUP, WHOIS, Subdomain, SSL ve E-Posta Header Analiz Aracı
Bu proje, PHP tabanlı bir web uygulamasıdır ve kullanıcıların DNS kayıtlarını sorgulamasına, WHOIS bilgilerini almasına, subdomainleri tespit etmesine, SSL sertifikalarını incelemesine, e-posta header'larını analiz etmesine ve IP/ASN ile blacklist kontrolleri yapmasına olanak tanır. Modern, kullanıcı dostu ve responsive bir arayüzle tasarlanmıştır.
Özellikler

DNS Kayıtları Sorgulama: A, CNAME, NS, MX, SOA ve TXT gibi DNS kayıtlarını listeler.
NSLOOKUP: Belirli bir DNS kayıt türü için detaylı sorgulama yapar.
WHOIS Sorgulama: Alan adı bilgilerini (kayıt tarihi, bitiş tarihi, nameserver'lar vb.) WhoisXMLAPI üzerinden çeker.
Subdomain Tespiti: Yaygın subdomainleri tarayarak mevcut olanları listeler.
SSL Sertifika Analizi: SSL sertifikasının geçerlilik durumu, veren kuruluş, başlangıç/bitiş tarihleri ve kalan gün sayısını gösterir.
E-Posta Header Analizi: E-posta header'larını analiz ederek SPAM olasılığını puanlar ve detaylı rapor sunar.
IP/ASN Bilgisi: IP adresi veya domain için konum, ISP ve organizasyon bilgilerini sağlar.
Blacklist Kontrolü: IP veya domainin popüler spam blacklist'lerinde yer alıp almadığını kontrol eder.
Responsive Tasarım: Bootstrap 5 ve özel CSS ile mobil uyumlu, modern arayüz.

Ekran Görüntüleri
Uygulamanın ana sayfası ve sekme yapısı.
DNS kayıtları sorgulama sonucu.
Kurulum

Gereksinimler:
PHP 7.4 veya üzeri
Web sunucusu (Apache, Nginx vb.)
WhoisXMLAPI anahtarı (WHOIS sorguları için)
file_get_contents veya cURL etkin
Bootstrap 5 (CDN üzerinden sağlanıyor)


Adımlar:
Depoyu klonlayın: git clone https://github.com/canwod/dnstools
Dosyaları web sunucunuza yükleyin.
index.php içinde WhoisXMLAPI anahtarınızı apiKey değişkenine ekleyin.
index.php dosyasını tarayıcınızda açın.



Kullanım

Ana sayfada istediğiniz sekme (DNS, NSLOOKUP, WHOIS, Subdomain, SSL, E-Posta Header, IP/ASN, Blacklist) seçin.
İlgili forma domain, IP veya e-posta header bilgisini girin.
"Sorgula" veya "Analiz Et" butonuna tıklayın.
Sonuçları tablo veya liste formatında görüntüleyin.

Teknolojiler

Backend: PHP
Frontend: HTML, CSS (özel stiller), Bootstrap 5
Fontlar: Inter (Google Fonts)
API'ler:
WhoisXMLAPI (WHOIS sorguları)
ipinfo.io (IP/ASN bilgisi)
RDAP.org (RDAP sorguları)


Kütüphaneler:
Bootstrap Icons
Bootstrap 5 (CDN)



Notlar

WHOIS Sorguları: WhoisXMLAPI anahtarı gereklidir. Ücretsiz bir anahtar için WhoisXMLAPI adresine kaydolabilirsiniz.
E-Posta Header Analizi: SPAM puanı, SPF, DKIM, DMARC ve diğer header özelliklerine göre hesaplanır. Kesin sonuçlar için profesyonel araçlarla doğrulama önerilir.
Blacklist Kontrolü: Popüler spam blacklist'lerini kontrol eder, ancak tam kapsamlı bir tarama için ek araçlar kullanılabilir.
SSL Sorguları: Bağlantı hatalarına karşı toleranslıdır, ancak bazı durumlarda sertifika bilgileri alınamayabilir.

Katkıda Bulunma
Katkılarınızı bekliyoruz! Lütfen aşağıdaki adımları izleyin:

Depoyu fork edin.
Yeni bir branch oluşturun: git checkout -b ozellik/yeni-ozellik
Değişikliklerinizi yapın ve commit edin: git commit -m "Yeni özellik eklendi"
Branch'i push edin: git push origin ozellik/yeni-ozellik
Bir Pull Request açın.

Lisans
Bu proje MIT Lisansı altında lisanslanmıştır.
İletişim
Sorularınız veya önerileriniz için GitHub Issues üzerinden iletişime geçebilirsiniz.

Uyarı: Bu araç bilgilendirme amaçlıdır. Güvenlik veya yasal işlemler için profesyonel hizmetler kullanılmalıdır.
