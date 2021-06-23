"""
Error messages, data and custom validation code used in
django-registration's various user-registration form classes.

"""
import re
import unicodedata

from confusable_homoglyphs import confusables
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator, RegexValidator
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _

CONFUSABLE = _("This name cannot be registered. " "Please choose a different name.")
CONFUSABLE_EMAIL = _(
    "This email address cannot be registered. "
    "Please supply a different email address."
)
DUPLICATE_EMAIL = _(
    "This email address is already in use. " "Please supply a different email address."
)
DUPLICATE_USERNAME = _("A user with that username already exists.")
FREE_EMAIL = _(
    "Registration using free email addresses is prohibited. "
    "Please supply a different email address."
)
RESERVED_NAME = _("This name is reserved and cannot be registered.")
TOS_REQUIRED = _("You must agree to the terms to register")

# WHATWG HTML5 spec, section 4.10.5.1.5.
HTML5_EMAIL_RE = (
    r"^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]"
    r"+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
    r"[a-zA-Z0-9])?(?:\.[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


# Below we construct a large but non-exhaustive list of names which
# users probably should not be able to register with, due to various
# risks:
#
# * For a site which creates email addresses from username, important
#   common addresses must be reserved.
#
# * For a site which creates subdomains from usernames, important
#   common hostnames/domain names must be reserved.
#
# * For a site which uses the username to generate a URL to the user's
#   profile, common well-known filenames must be reserved.
#
# etc., etc.
#
# Credit for basic idea and most of the list to Geoffrey Thomas's blog
# post about names to reserve:
# https://ldpreload.com/blog/names-to-reserve
SPECIAL_HOSTNAMES = [
    # Hostnames with special/reserved meaning.
    "autoconfig", "autodiscover", "broadcasthost", "isatap", "localdomain",  
    "localhost", "wpad",
]


PROTOCOL_HOSTNAMES = [
    # Common protocol hostnames.
    "bittorent", "idna", "soap", "rtcp", "xmpp", "dccp", "sctp", "isdn", "dtm", "gtp", "ftp",
    "imap", "mail", "news", "pop", "pop3", "sdp", "smtp", "smb", "cifs", "irc", "netbeui",
    "gprs", "rarp", "usenet", "rvsp", "gopher", "uucp", "webmail", "www", "bgp", "dhcp",
    "ftp", "sftp", "dns", "ldap", "icmp", "igmp", "arp", "ndp", "ospf", "ppp", "mac",
    "msnp", "bit", "dsl", "fddi", "ipsec", "ethernet", "snmp", "ssh", "telnet", "tftp",
    "mqtt", "nntp", "ntp", "pop", "pptp", "tls", "ssl", "sip", "http", "https", "rap",
    "rsvp", "rtp", "spx", "netware", "ipx", "ncp", "nfs", "upnp", "radius", "vnc", "wins",
    "kerberos", "finger", "whois", "echo", "tacacs", "bootp", "rpc", "xdmcp", "appletalk",
    "openvpn", "vpn",
]

STOP_WORDS = [
    "about", "above", "across", "after", "afterwards", "again", "against", "all", "ain",
    "almost", "alone", "along", "already", "also", "although", "always", "am", "among",
    "amongst", "amoungst", "amount", "an", "and", "another", "any", "anyhow", "anyone", "anything",
    "anyway", "anywhere", "are", "aren", "around", "as", "at", "back", "be", "became",
    "because", "become", "becomes", "becoming", "been", "before", "beforehand", "behind",
    "being", "below", "beside", "besides", "between", "beyond", "bill", "both", "bottom",
    "but", "by", "call", "can", "cannot", "cant", "co", "computer", "con", "could", "couldnt",
    "cry", "de", "describe", "detail", "do", "done", "down", "due", "during", "each", "eg",
    "eight", "either", "eleven", "else", "elsewhere", "empty", "enough", "etc", "even", "ever",
    "every", "everyone", "everything", "everywhere", "except", "few", "fifteen", "fify",
    "fill", "find", "fire", "first", "five", "for", "former", "formerly", "forty", "found", "four",
    "from", "front", "full", "further", "get", "give", "go", "had", "has", "hasnt", "have", "he",
    "hence", "her", "here", "hereafter", "hereby", "herein", "hereupon", "hers", "herse", "him",
    "himse", "his", "how", "however", "hundred", "i", "ie", "if", "in", "inc", "indeed", "interest",
    "into", "is", "it", "its", "itself", "itse", "keep", "last", "latter", "latterly", "least", "less",
    "ltd", "made", "many", "may", "me", "meanwhile", "might",  "mill", "mine", "more", "moreover",
    "most", "mostly", "move", "much", "must", "my", "mysel", "name", "namely", "neither", "never",
    "nevertheless", "next", "nine", "no", "nobody", "none", "noone", "nor", "not", "nothing",
    "now", "nowhere", "of", "off", "often", "on", "once", "one", "only","onto", "or", "other",
    "others", "otherwise", "our", "ours", "ourselves", "out", "over", "own", "part", "per", "perhaps",
    "please", "put", "rather", "re", "same", "see", "seem", "seemed", "seeming", "seems", "serious",
    "several", "she", "should", "show", "side", "since", "sincere", "six", "sixty", 
    "so", "some", "somehow", "someone", "something","sometime", "sometimes", "somewhere",
    "still", "such", "system", "take", "ten", "than", "that", "the", "their", "them", "themselves",
    "then", "thence", "there", "thereafter", "thereby", "therefore", "therein", "thereupon", "these",
    "they", "thick", "thin", "third", "this", "those", "though", "three", "through", "throughout",
    "thru", "thus", "to", "together", "too", "top", "toward", "towards", "twelve", "twenty",
    "two", "un", "under", "until", "up", "upon", "us", "very", "via", "was", "we", "wasn",
    "weren", "well", "were", "what", "whatever", "when", "whence", "whenever", "where", "whereafter",
    "whereas", "whereby", "wherein", "whereupon", "wherever", "whether", "which", "while",
    "whither", "who", "whoever", "whole", "whom", "whose", "why", "will", "with", "within",
    "without", "would", "wouldn", "won", "yet", "you", "your", "yours", "yourself", "yourselves",
]

BRANDS = [
    "aoc", "aldelco", "apache", "audi", "akadema", "avon", "aig", "adata", "astonmartin", "alfaromeo", "apple", "arris", "annazaradna", "asrock", "abtivan", "ainope", "alienware", "aiwa", "att", "annique", "alturaphoto", "amd", "acura", "aiko", "adobe", "asus", "arlo", "aws",
    "activision", "allianz", "android", "airbnb", "aeropostale", "amazon", "americanexpress", "adidas", "accenture", "autodesk", "alibaba", "adaptec", "spalding", "sigma", "sears", "supersonic", "suzuki", "saturn", "sceptre", "sanyo", "skoda", "siemens", "sprite", "stella", "sharppebble", "starbucks", "spectrum", "subaru", "subway", "shopify", "skydio", "singer", "synology", "yahoo", "yongnuo", "yeepin", "yamaha", "yelp", "youtube", "zorrosounds", "zscaler", "zyxel", "zotac", "zillow", "zillow", "zara", "walgreens", "wilson", "wrigley", "westinghouse", "worldofthis", "warnerbrothers", "wellsfargo", "wellsfargo", "xidax", "xiaomi", "xmart", "whirlpool", "wacom", "wayfair", "westernunion", "wynd", "wikipedia", "westerndigital", "walmart", "windows", "xerox", "xiaomi", "xiaomi", "xfinity", "vodafone", "vespa", "visa", "verizon", "vitade", "versace", "viagra", "vtech", "viewsonic", "vmware", "vaio", "volkswagen", "victoriassecret", "volvo", "verizon", "ubisoft", "ubeesize", "ubiquiti", "unilever", "uber", "ups", "vizio", "opel", "oldelpaso", "otterbox", "ralphlauren", "revlon", "oracle", "rover", "rexona", "roku", "reuters", "qnap", "reebok", "razer", "russelhobbs", "rollsroyce", "rowenta", "playboy", "plymouth", "philips", "panasonic", "polestar", "practiker", "paloaltonetworks", "pillsbury", "pontiac", "peugeot", "paypal", "pepsi", "playstation", "pfsense", "porsche", "prada", "polaroid", "toshiba", "tivo", "tefal", "target", "tuffy", "tplink", "terramaster", "tyan", "transcend", "tiffany", "tenda", "twitch", "sandisk", "squarespace", "splunk", "swarovski", "siata", "shelby", "toyota", "tissot", "tencent", "nissan", "newegg", "neo", "netflix", "netgear", "nintendo", "google", "samsung" , "seagate", "seiko", "sonicwall", "nava", "nvidia", "nginx", "nestle", "brentwood", "bing", "buick", "burgerking", "bugatti", "budlight", "belkin", "biocera", "bmw", "bose", "brita", "bentley", "budweiser", "burberry", "broadcom", "biostar", "brocade", "blizzard", "bestbuy", "boeing", "cocacola", "camco", "cyberpower", "chrysler", "cadillac", "chevron", "compucase", "citizen", "citrix", "crown", "creativelabs", "cisco", "cuisinart", "colgate", "calvinklein", "cnn", "citroen", "cheerios", "chase", "canon", "chanel", "cartier", "hsbc", "hulu", "disney", "danone", "dewalt", "diesel", "deegotech", "dior", "dell", "duracell", "daewoo", "doordash", "dowjones", "domestos", "dominos", "gucci", "dyson", "facebook", "fiat", "hyundai", "hellmanns", "equinox", "ikea", "intel", 
]


COUNTRIES = [
    "afghanistan", "albania", "algeria", "andorra", "angola", "antigua", "argentina", "armenia", "australia", "austria", "azerbaijan", "bahamas", "bahrain", "barbados", "belarus", "belgium", "belize", "benin", "bhutan", "bolivia", "botswana", "bosnia", "brazil", "brunei", "bulgaria", "burkinafaso", "burkina", "burundi", "cambodia", "cameroon", "canada", "chad", "chile", "china", "colombia", "comoros", "congo", "costarica", "croatia", "cuba", "cyprus", "czechia", "denmark", "djibouti", "dominica", "ecuador", "egypt", "elsalvador", "eritrea", "estonia", "ethiopia", "fiji", "finland", "france", "gabon", "gambia", "georgia", "germany", "ghana", "greece", "grenada", "guatemala", "guinea", "guyana", "haiti", "honduras", "hungary", "iceland", "india", "indonesia", "iran", "iraq", "ireland", "israel", "italy", "jamaica", "japan", "jordan", "kazakhstan", "kenya", "kiribati", "kuwait", "kyrgyzstan", "laos", "latvia", "lebanon", "lesotho", "liberia", "libya", "liechtenstein", "lithuania", "luxembourg", "madagascar", "malawi", "malaysia", "maldives", "mali", "malta", "marshallislands", "mauritania", "mauritius", "mexico", "micronesia", "moldova", "monaco", "mongolia", "montenegro", "morocco", "mozambique", "myanmar", "namibia", "nauru", "nepal", "netherlands", "newzealand", "nicaragua", "niger", "nigeria", "northkorea", "northmacedonia", "macedonia", "norway", "oman", "pakistan", "palau", "panama", "palestine", "panama", "paraguay", "peru", "philippines", "poland", "portugal", "qatar", "romania", "russia", "rwanda", "samoa", "sanmarino", "saudiarabia", "senegal", "serbia", "seychelles", "sierraleone", "singapore", "slovakia", "slovenia", "somalia", "southafrica", "southkorea", "southsudan", "sudan", "spain", "srilanka", "suriname", "sweden", "switzerland", "syria", "tajikistan", "tanzania", "thailand", "togo", "tonga", "trinidad", "tobago", "tunisia", "turkey", "turkmenistan", "tuvalu", "uganda", "ukraine", "uruguay", "unitedstatesofamerica", "america", "usa", "uzbekistan", "vanuatu", "venezuela",  "vietnam",  "yemen",  "zambia",  "zimbabwe",
]

CA_ADDRESSES = [
    # Email addresses known used by certificate authorities during
    # verification.
    "admin", "superadmin", "superuser", "administrator", "hostmaster", "info", "is",
    "it", "mis", "postmaster", "root", "toor", "ssladmin", "ssladministrator", "sslwebmaster",
    "sysadmin", "webmaster",
]

RFC_2142 = [
    # RFC-2142-defined names not already covered.
    "abuse", "marketing", "noc", "sales", "security", "support",
]

NOREPLY_ADDRESSES = [
    # Common no-reply email addresses.
    "mailer-daemon", "nobody", "noreply", "no-reply",
]

SENSITIVE_FILENAMES = [
    # Sensitive filenames.
    "clientaccesspolicy.xml", "crossdomain.xml",  "favicon.ico", "humans.txt",
    "keybase.txt","robots.txt", ".htaccess", ".htpasswd",
]

OTHER_SENSITIVE_NAMES = [
    # Other names which could be problems depending on URL/subdomain
    # structure.
    "account", "accounts", "auth", "authorize", "blog", "buy", "create", "cart", "clients",
    "contact", "contactus", "contact-us", "checkout", "copyright", "dashboard", "doc", "docs",
    "download", "downloads", "enquiry", "faq", "edit", "help", "inquiry", "license", "login",
    "logout", "me", "myaccount", "new", "oauth", "pay", "payment", "payments", "plans",
    "portfolio", "preferences", "pricing", "privacy", "profile", "register", "secure",
    "settings", "signin", "signup", "ssl", "ssdp", "status", "superroot", "store",
    "subscribe", "reset", "resets", "terms", "tos", "user", "users", "update", "weblog", "work",
    "password", "passwords", "route", "routes", "view", "views", "token", "tokens", "slug", "slugs",
    "path", "paths", "url", "urls", "base", "app", "apps", "test", "tests", "settings", 
    "event", "events", "updates", "context", "contexts", "person", "detail",
    "details", "item", "items", "form", "forms", "delete", "update", "snippets", "snippet",
    "places", "place", "food", "recipe", "job", "jobs", "solution", "solutions",
]

FILE_EXTENSIONS = [
    "asp", "aspx", "arj", "apk", "aiff", "aif", "avi", "bat", "bak", "bin", "bmp", "cda", "cue",
    "cpp", "cab", "cfg", "cpl", "cur", "cgi", "csr", "cer", "cfm", "css", "com", "class",
    "java", "jsp", "csv", "cvs", "deb", "dat", "dbf", "dll", "dmp", "drv", "dmg", "dwg",
    "dxf", "dif", "dtd", "doc", "docx", "eps", "email", "eml", "emlx", "exe", "flv", "fnt",
    "iso", "icns", "ini", "ico", "gadget", "gif", "gpx", "hqx", "htm", "heic", "html", "jpg",
    "jar", "jpeg", "kmz", "mac", "msi", "max", "mkv", "mpa", "msg", "map", "mdb", "mdf", "mid",
    "midi", "mov", "mpg", "mpeg", "lnk", "lua", "log", "nes", "png", "pdf", "part", "php", "ppt",
    "pkg", "pptx", "psd", "psp", "pst", "prf", "rom", "rtf", "rss", "rar", "rpm", "sit", "sys",
    "srt", "swf", "sql", "sln", "swift", "tar", "tif", "ttf", "tmp", "thm", "tex", "tiff", "torrent",
    "txt", "svg", "odt", "ods", "ogg", "otf", "oft", "ost", "vcd", "vcf", "vob", "vcxproj", "wav",
    "wsf", "wma", "wmv", "wpd", "wpl", "wpd", "wps", "xlsm", "xml", "xhtml", "xls", "xlsx",
    "zip", "zipx",
]

HTML_TAGS = [
    "abbr", "address", "applet", "area", "audio", "base", "basefont", "bdi", "blockquote",
    "code", "video", "var", "table", "summary", "tbody", "title", "thead", "track", "svg",
    "sub", "sup", "style", "span", "div", "source", "small", "section", "article", "progress",
    "picture", "figure", "param", "object", "noscript", "nav", "meter", "meta", "main", "mark",
    "header", "body", "html", "iframe", "label", "kbd", "legend", "link", "map", "img", "head",
    "figcaption", "embed", "fieldset", "dialog", "details", "datalist", "canvas", "button", 
    "script", "select", "center", "strike", "textarea", "source", "option", "optgroup", "object",
    "font", "acronym",
]

TECH = [
    "python", "java", "php", "jquery", "javscript", "bootstrap", "java", "sql", "css", "rust",
    "django", "flask", "laravel",
]

RACIST_WORDS = [
    "yankee", "redskin", "russki", "chink", "coon", "colored", "niggar", "nigger",
    "nigglet", "niglet", "hick", "whitey", "trash", "negro", "raghead",
]


DEFAULT_RESERVED_NAMES = (
    SPECIAL_HOSTNAMES
    + PROTOCOL_HOSTNAMES
    + CA_ADDRESSES
    + RFC_2142
    + NOREPLY_ADDRESSES
    + SENSITIVE_FILENAMES
    + OTHER_SENSITIVE_NAMES
    + STOP_WORDS
    + FILE_EXTENSIONS
    + RACIST_WORDS
    + HTML_TAGS
    + TECH
    + BRANDS
    + COUNTRIES
)


@deconstructible
class ReservedNameValidator:
    """
    Validator which disallows many reserved names as form field
    values.
    """

    def __init__(self, reserved_names=DEFAULT_RESERVED_NAMES):
        self.reserved_names = reserved_names

    def __call__(self, value):
        # GH issue 82: this validator only makes sense when the
        # username field is a string type.
        if not isinstance(value, str):
            return
        if value in self.reserved_names or value.startswith(".well-known"):
            raise ValidationError(RESERVED_NAME, code="invalid")

    def __eq__(self, other):
        return self.reserved_names == other.reserved_names


@deconstructible
class CaseInsensitiveUnique:
    """
    Validator which performs a case-insensitive uniqueness check.

    """

    def __init__(self, model, field_name, error_message):
        self.model = model
        self.field_name = field_name
        self.error_message = error_message

    def __call__(self, value):
        # Only run if the username is a string.
        if not isinstance(value, str):
            return
        value = unicodedata.normalize("NFKC", value).casefold()
        if self.model._default_manager.filter(
            **{"{}__iexact".format(self.field_name): value}
        ).exists():
            raise ValidationError(self.error_message, code="unique")

    def __eq__(self, other):
        return (
            self.model == other.model
            and self.field_name == other.field_name
            and self.error_message == other.error_message
        )


@deconstructible
class HTML5EmailValidator(RegexValidator):
    """
    Validator which applies HTML5's email address rules.

    """

    message = EmailValidator.message
    regex = re.compile(HTML5_EMAIL_RE)


def validate_confusables(value):
    """
    Validator which disallows 'dangerous' usernames likely to
    represent homograph attacks.

    A username is 'dangerous' if it is mixed-script (as defined by
    Unicode 'Script' property) and contains one or more characters
    appearing in the Unicode Visually Confusable Characters file.

    """
    if not isinstance(value, str):
        return
    if confusables.is_dangerous(value):
        raise ValidationError(CONFUSABLE, code="invalid")


def validate_confusables_email(value):
    """
    Validator which disallows 'dangerous' email addresses likely to
    represent homograph attacks.

    An email address is 'dangerous' if either the local-part or the
    domain, considered on their own, are mixed-script and contain one
    or more characters appearing in the Unicode Visually Confusable
    Characters file.

    """
    # Email addresses are extremely difficult.
    #
    # The current RFC governing syntax of email addresses is RFC 5322
    # which, as the HTML5 specification succinctly states, "defines a
    # syntax for e-mail addresses that is simultaneously too strict
    # ... too vague ...  and too lax ...  to be of practical use".
    #
    # In order to be useful, this validator must consider only the
    # addr-spec portion of an email address, and must examine the
    # local-part and the domain of that addr-spec
    # separately. Unfortunately, there are no good general-purpose
    # Python libraries currently available (that the author of
    # django-registration is aware of), supported on all versions of
    # Python django-registration supports, which can reliably provide
    # an RFC-complient parse of either a full address or an addr-spec
    # which allows the local-part and domain to be treated separately.
    #
    # To work around this shortcoming, RegistrationForm applies the
    # HTML5 email validation rule, which HTML5 admits (in section
    # 4.10.5.1.5) is a "willful violation" of RFC 5322, to the
    # submitted email address. This will reject many technically-valid
    # but problematic email addresses, including those which make use
    # of comments, or which embed otherwise-illegal characters via
    # quoted-string.
    #
    # That in turn allows this validator to take a much simpler
    # approach: it considers any value containing exactly one '@'
    # (U+0040) to be an addr-spec, and consders everything prior to
    # the '@' to be the local-part and everything after to be the
    # domain, and performs validation on them. Any value not
    # containing exactly one '@' is assumed not to be an addr-spec,
    # and is thus "accepted" by not being validated at all.
    if value.count("@") != 1:
        return
    local_part, domain = value.split("@")
    if confusables.is_dangerous(local_part) or confusables.is_dangerous(domain):
        raise ValidationError(CONFUSABLE_EMAIL, code="invalid")
