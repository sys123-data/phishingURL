import time

import pandas as pd
from urllib.parse import urlparse,urlencode
import ipaddress
import re
import requests

data_00 = pd.read_csv("datasets/verified_online.csv")
phishing_URL = data_00.sample(n = 5000, random_state = 12).copy()
phishing_URL = phishing_URL.reset_index(drop=True)
data_01 = pd.read_csv("datasets/big_list.csv")
data_01.columns = ['URLs']
URL_inofensiv = data_01.sample(n = 5000, random_state = 12).copy()
URL_inofensiv = URL_inofensiv.reset_index(drop=True)


def obtineDomeniu(adresa_url):
    # Extragem domeniul din adresa url

    # domeniul = urlparse(adresa_url).netloc

    if re.findall(r'://.+?/', adresa_url) == []: return 0

    return re.findall(r'://.+?/', adresa_url)[0][3:-1]

def contineIP(adresa_url):
    # Returnam 0 sau 1 daca adresa nu contine IP respective daca contine

    try: ipaddress.ip_address(adresa_url)

    except: return  0

    return 1


def contineSemnul(adresa_url):
    # Returneaza prezenta @ in adresa url```

    if "@" in adresa_url: return 1

    return 0


def obtineLungimea(adresa_url):
    # Returneaza 1 daca adresa url este mai lunga de 53 de caractere altfel 0

    if not (len(adresa_url) < 54):  return 1

    return 0


def obtineAdancimea(adresa_url):
    # Returneaza adancimea URL-ului

    adancimea = 0

    lista_sub_siteuri = urlparse(adresa_url).path.split('/')

    for _ in range(len(lista_sub_siteuri)):
        if len(lista_sub_siteuri[_]) < 1: adancimea += 1

    return adancimea

def redirectionareURL(adresa_url):
  # Returneaza 1 daca exista // in alta parte decat in HTTP(S)://

    pozitia = adresa_url.rfind('//')

    if pozitia > 6:

        if pozitia > 7: return 1

    return 0

def domeniuHTTP(adresa_url):
  # Returneaza 1 daca url contine http(s) in domeniu, 0 altfel

    domeniu = urlparse(adresa_url).netloc

    if 'https' in domeniu or 'http' in domeniu: return 1

    return 0

lista_servicii_prescurtare_url = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"


def URLScurte(adresa_url):
    # Returneaza 0 daca url scurt apartine listei de url-uri permise

    if re.search(lista_servicii_prescurtare_url, adresa_url): return 1

    return 0

import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime


def sufixPrefix(adresa_url):
    # Dacă există – in domeniu url returnam 1, altfel 0

    if '-' in urlparse(adresa_url).netloc: return 1

    return 0

def traficWeb(adresa_url):
  # Retuneaza 1 daca url nu este gasit sau nu este in primele 100000 de adrese, altfel returneaza 0

    try:
        adresa_url = urllib.parse.quote(adresa_url)
        clasament = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + adresa_url).read(), "html.parser").find("REACH")['RANK']
        clasament = int(clasament)
    except TypeError:
        return 1
    if clasament <100000: return 1
    return 0


def varstaDomeniu(nume_domeniu):
    # Returneza 1 daca nu există, are relansari sau are mai putin de 6 luni

    data_creare = nume_domeniu.creation_date

    data_expirare = nume_domeniu.expiration_date

    if isinstance(data_creare, str) or isinstance(data_expirare, str):
        try:

            data_creare = datetime.strptime(data_creare, '%Y-%m-%d')

            data_expirare = datetime.strptime(data_expirare, "%Y-%m-%d")

        except:

            return 1

    if (data_expirare is None) or (data_creare is None): return 1

    if (type(data_expirare) is list) or (type(data_creare) is list): return 1

    if (((data_expirare - data_creare).days) / 30) < 6: return 1

    return 0


def valabilitateaDomeniuliu(nume_domeniu):
    # Returneaza 0 daca valabilitatea este de peste 6 luni

    data_expirare = nume_domeniu.expiration_date

    if isinstance(data_expirare, str):
        try:
            data_expirare = datetime.strptime(data_expirare, "%Y-%m-%d")
        except:
            return 1

    if data_expirare is None: return 1

    if type(data_expirare) is list: return 1

    if (((data_expirare - datetime.now()).days) / 30) < 6: return 0

    return 1


def validareIFrame(raspuns):
    # Returneaza 0 daca exista iframe sau frameborder

    if raspuns.text == "": return 1

    #if re.findall(r"[<iframe>|<frameBorder>]", raspuns.text): return 0

    if "iframe" in raspuns.text or "frameBorder" in raspuns.text: return 0

    return 1


def cautamEventMouseOver(raspuns):
    # Return 1 daca raspunsul este gol sau daca conține onMouseOver

    if raspuns.text == "": return 1

    if re.findall("<script>.+onmouseover.+</script>", raspuns.text):
        return 1

    return 0


def verificareClicDreapta(raspuns):
    # Verificam daca raspunsul exista sau daca contine event.button==2

    if raspuns.text == "": return 1

    if re.findall(r"event.button ?== ?2", raspuns.text): return 1

    return 0


def redirectionareCatreAltURL(raspuns):
    if raspuns.text == "":  return 1

    if len(raspuns.history) > 2:     return 1

    return 0


def determinareCaracteristici(adresa_url):
    caracteristici = []

    # Bara de adrese [10]

    caracteristici.append(obtineDomeniu(adresa_url))
    #print(1)
    caracteristici.append(contineIP(adresa_url))
    #print(2)
    caracteristici.append(contineSemnul(adresa_url))
    #print(3)
    caracteristici.append(obtineLungimea(adresa_url))
    #print(4)
    caracteristici.append(obtineAdancimea(adresa_url))
    #print(5)
    caracteristici.append(redirectionareURL(adresa_url))
    #print(6)
    caracteristici.append(domeniuHTTP(adresa_url))
    #print(7)
    caracteristici.append(URLScurte(adresa_url))
    #print(8)
    caracteristici.append(sufixPrefix(adresa_url))
    #print(9)
    # Caracteristici domneniu [4]
    domeniu = False
    try:
        nume_domeniu = whois.whois(urlparse(adresa_url).netloc)
    except:
        domeniu = True
    #print(10)
    caracteristici.append(int(domeniu))
    #print(11)
    caracteristici.append(traficWeb(adresa_url))
    #print(12)
    caracteristici.append(1 if domeniu else varstaDomeniu(nume_domeniu))
    #print(13)
    caracteristici.append(1 if domeniu else valabilitateaDomeniuliu(nume_domeniu))
    #print(14)
    # Caracteristici HTML si Javascript [4]

    try:

        raspuns = requests.get(adresa_url,timeout=3)
    except:
        raspuns = ""
    print(raspuns)
    x = time.perf_counter()
    print(raspuns.content)
    if time.perf_counter()-x < 3:

        if raspuns!="":
            if str(raspuns.status_code) == "200":

                print(15)
                caracteristici.append(validareIFrame(raspuns))
                print(16)
                caracteristici.append(cautamEventMouseOver(raspuns))
                #print(17)
                caracteristici.append(verificareClicDreapta(raspuns))
                #print(18)
                caracteristici.append(redirectionareCatreAltURL(raspuns))
                #print(19)
                ##caracteristici.append(eticheta)
                #print(20)
        else:
            caracteristici+=[1]+[1]+[1]+[1]+[1]

    return caracteristici

caracteristici_inofensive = []
#eticheta = 0

print("URL_inofensiv\n",URL_inofensiv)


# for _ in range(0, 5000):
#     print (_)
#     adresa_url = URL_inofensiv['URLs'][_]
#     print(adresa_url)
#     print(URL_inofensiv['URLs'][_+1])
#     caracteristici_inofensive+=[determinareCaracteristici(adresa_url)]
#     #eticheta +=1

adresa_url="http://sourceforge.net/projects/exo/files/latest/download?source=frontpage&position=1"
print(adresa_url)
#caracteristici_inofensive+=[determinareCaracteristici(adresa_url)]
#print(caracteristici_inofensive)
print(obtineDomeniu(adresa_url))