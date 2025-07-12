feature_names = [
    "UsingIp",
    "LongURL",
    "ShortURL",
    "Symbol@",
    "Redirecting",
    "PrefixSuffix",
    "SubDomains",
    "HTTPS",
    "DomainRegLen",
    "Favicon",
    "NonStdPort",
    "HTTPSDomainURL",
    "RequestURL",
    "AnchorURL",
    "LinksInScriptTags",
    "ServerFormHandler",
    "InfoEmail",
    "AbnormalURL",
    "WebsiteForwarding",
    "StatusBarCust",
    "DisableRightClick",
    "UsingPopupWindow",
    "IframeRedirection",
    "AgeofDomain",
    "DNSRecording",
    "WebsiteTraffic",
    "PageRank",
    "GoogleIndex",
    "LinksPointingToPage",
    "StatsReport",
]

feature_explanations = {
    "UsingIp": {
        1: "✅ URL ini tidak menggunakan alamat IP, yang lebih aman.",
        0: "⚠️ URL ini netral terkait penggunaan IP.",
        -1: "❌ URL ini menggunakan alamat IP sebagai domain, yang sering digunakan oleh situs phishing.",
    },
    "LongURL": {
        1: "✅ URL ini memiliki panjang yang wajar.",
        0: "⚠️ URL ini agak panjang, periksa dengan hati-hati.",
        -1: "❌ URL ini sangat panjang, yang bisa menjadi indikasi phishing.",
    },
    "ShortURL": {
        1: "✅ URL ini tidak menggunakan layanan pemendek link.",
        0: "⚠️ URL ini netral terkait pemendekan.",
        -1: "❌ URL ini menggunakan pemendek link, yang bisa menyembunyikan URL asli.",
    },
    "Symbol@": {
        1: "✅ URL ini tidak mengandung simbol '@', yang lebih aman.",
        0: "⚠️ Tidak ada informasi jelas mengenai simbol '@'.",
        -1: "❌ URL ini mengandung '@', yang sering digunakan dalam phishing.",
    },
    "Redirecting": {
        1: "✅ URL tidak melakukan pengalihan berlebihan.",
        0: "⚠️ URL memiliki beberapa pengalihan, periksa lebih lanjut.",
        -1: "❌ URL ini melakukan banyak pengalihan, yang sering digunakan dalam phishing.",
    },
    "PrefixSuffix": {
        1: "✅ URL ini tidak mengandung tanda '-', lebih aman.",
        0: "⚠️ URL ini netral terhadap penggunaan '-'.",
        -1: "❌ URL ini memiliki tanda '-', yang sering digunakan dalam phishing.",
    },
    "SubDomains": {
        1: "✅ URL ini hanya memiliki satu subdomain, lebih aman.",
        0: "⚠️ URL memiliki dua subdomain, perlu diperiksa lebih lanjut.",
        -1: "❌ URL memiliki banyak subdomain, yang sering digunakan dalam phishing.",
    },
    "HTTPS": {
        1: "✅ Website ini menggunakan HTTPS, lebih aman.",
        0: "⚠️ Tidak ada informasi tentang penggunaan HTTPS.",
        -1: "❌ Website ini tidak menggunakan HTTPS, yang berisiko.",
    },
    "DomainRegLen": {
        1: "✅ Domain terdaftar lebih dari 1 tahun, lebih aman.",
        0: "⚠️ Domain ini cukup baru, perlu kehati-hatian.",
        -1: "❌ Domain terdaftar dalam waktu singkat, berisiko.",
    },
    "Favicon": {
        1: "✅ Favicon berasal dari domain utama, lebih aman.",
        -1: "❌ Favicon berasal dari domain lain, bisa mencurigakan.",
    },
    "NonStdPort": {
        1: "✅ Website menggunakan port standar, lebih aman.",
        -1: "❌ Website menggunakan port tidak standar, berisiko.",
    },
    "HTTPSDomainURL": {
        1: "✅ HTTPS digunakan pada domain utama.",
        -1: "❌ HTTPS tidak digunakan dengan benar, bisa mencurigakan.",
    },
    "RequestURL": {
        1: "✅ Mayoritas sumber daya berasal dari domain sendiri.",
        0: "⚠️ Beberapa sumber daya berasal dari domain lain.",
        -1: "❌ Banyak sumber daya berasal dari domain eksternal, berisiko.",
    },
    "AnchorURL": {
        1: "✅ Sebagian besar link tetap berada dalam domain ini.",
        0: "⚠️ Beberapa link mengarah ke domain lain.",
        -1: "❌ Banyak link mengarah ke domain lain, berisiko.",
    },
    "LinksInScriptTags": {
        1: "✅ Hanya sedikit link dalam script, lebih aman.",
        0: "⚠️ Beberapa link dalam script perlu diperiksa.",
        -1: "❌ Banyak link dalam script, bisa berisiko.",
    },
    "ServerFormHandler": {
        1: "✅ Formulir mengarah ke domain sendiri.",
        0: "⚠️ Beberapa formulir mengarah ke domain lain.",
        -1: "❌ Formulir mengarah ke domain lain, bisa mencurigakan.",
    },
    "InfoEmail": {
        1: "✅ Tidak ditemukan alamat email mencurigakan.",
        -1: "❌ Ada email mencurigakan di halaman ini.",
    },
    "AbnormalURL": {
        1: "✅ URL sesuai dengan informasi WHOIS.",
        -1: "❌ URL berbeda dengan informasi WHOIS, berisiko.",
    },
    "WebsiteForwarding": {
        1: "✅ Tidak ada atau sedikit pengalihan.",
        0: "⚠️ Beberapa pengalihan terdeteksi.",
        -1: "❌ Banyak pengalihan, berisiko.",
    },
    "StatusBarCust": {
        1: "✅ Status bar tidak dimanipulasi.",
        -1: "❌ Status bar dimanipulasi oleh script, berisiko.",
    },
    "DisableRightClick": {
        1: "✅ Klik kanan diizinkan.",
        -1: "❌ Klik kanan dinonaktifkan, bisa mencurigakan.",
    },
    "UsingPopupWindow": {
        1: "✅ Tidak ada jendela popup mencurigakan.",
        -1: "❌ Jendela popup mencurigakan terdeteksi.",
    },
    "IframeRedirection": {
        1: "✅ Tidak ada iframe mencurigakan.",
        -1: "❌ Terdapat iframe tersembunyi, berisiko.",
    },
    "AgeofDomain": {
        1: "✅ Domain sudah ada cukup lama.",
        -1: "❌ Domain baru, perlu diperiksa lebih lanjut.",
    },
    "DNSRecording": {
        1: "✅ DNS memiliki catatan yang valid.",
        -1: "❌ Tidak ada catatan DNS, berisiko.",
    },
    "WebsiteTraffic": {
        1: "✅ Website memiliki trafik tinggi.",
        0: "⚠️ Website memiliki trafik sedang.",
        -1: "❌ Website memiliki trafik rendah atau tidak ada.",
    },
    "PageRank": {
        1: "✅ Website memiliki PageRank tinggi.",
        0: "⚠️ Website memiliki PageRank sedang.",
        -1: "❌ Website memiliki PageRank rendah.",
    },
    "GoogleIndex": {
        1: "✅ Website ini terindeks di Google.",
        -1: "❌ Website ini tidak terindeks di Google.",
    },
    "LinksPointingToPage": {
        1: "✅ Banyak link yang mengarah ke halaman ini.",
        0: "⚠️ Beberapa link mengarah ke halaman ini.",
        -1: "❌ Tidak ada link yang mengarah ke halaman ini.",
    },
    "StatsReport": {
        1: "✅ Tidak ada laporan mencurigakan.",
        -1: "❌ Website ini pernah dilaporkan sebagai phishing.",
    },
    "UsingIp": {
        1: "✅ URL ini tidak menggunakan alamat IP, yang lebih aman.",
        0: "⚠️ URL ini netral terkait penggunaan IP.",
        -1: "❌ URL ini menggunakan alamat IP sebagai domain, yang sering digunakan oleh situs phishing.",
    },
    "LongURL": {
        1: "✅ URL ini memiliki panjang yang wajar.",
        0: "⚠️ URL ini agak panjang, periksa dengan hati-hati.",
        -1: "❌ URL ini sangat panjang, yang bisa menjadi indikasi phishing.",
    },
    "ShortURL": {
        1: "✅ URL ini tidak menggunakan pemendek link.",
        0: "⚠️ URL ini netral terkait pemendekan.",
        -1: "❌ URL ini menggunakan layanan pemendek link, yang sering menyembunyikan URL asli.",
    },
    "HTTPS": {
        1: "✅ Website ini menggunakan HTTPS, yang lebih aman.",
        0: "⚠️ Tidak ada informasi jelas mengenai HTTPS.",
        -1: "❌ Website ini tidak menggunakan HTTPS, yang bisa membahayakan keamanan data.",
    },
    "GoogleIndex": {
        1: "✅ Website ini terindeks di Google, yang menandakan kepercayaan lebih tinggi.",
        0: "⚠️ Tidak ada informasi mengenai indeks Google.",
        -1: "❌ Website ini tidak terindeks di Google, yang bisa mencurigakan.",
    },
    "WebsiteTraffic": {
        1: "✅ Website ini memiliki trafik tinggi, menunjukkan popularitas yang lebih besar.",
        0: "⚠️ Website ini memiliki trafik sedang.",
        -1: "❌ Website ini memiliki trafik rendah atau tidak ada, yang bisa menjadi indikasi phishing.",
    },
    "PageRank": {
        1: "✅ Website ini memiliki PageRank tinggi, menunjukkan kredibilitas yang lebih baik.",
        0: "⚠️ Website ini memiliki PageRank sedang.",
        -1: "❌ Website ini memiliki PageRank rendah, yang bisa menjadi indikasi kurang terpercaya.",
    },
}
