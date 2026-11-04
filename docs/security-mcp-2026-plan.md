> **Aktualizacja 2026-11-04:** poniższy dokument zachowuje historyczny audyt i plan. Implementacja, odstępstwa zaakceptowane w zakresie zachowania core, dowody i ryzyko końcowe są w [raporcie wykonania](security-migration-status.md).

Audyt bezpieczeństwa i plan migracji ESET-MCP — 25 września 2026
==============================================================

Zakres: ESET Connect Cloud oraz ESET PROTECT On-Prem, commit
`442dcadadcfde802cf0b7ccb1955438ed20fcf15`. Sprawdzono kod, publiczną
dokumentację producentów i zachowanie na syntetycznym API. Nie wykonano
żadnego wywołania do rzeczywistego środowiska ESET. Dodano materiały audytu
i testy; kod produkcyjny oraz konfiguracja wdrożenia pozostają bez zmian.

**Wniosek.** Problem ma charakter architektoniczny: serwer nie ustanawia
jednolitej granicy poufności między uwierzytelnianiem, danymi z API i treścią
MCP widoczną dla modelu. Dodatkowo model izolacji oparty na ContextVar nie
odpowiada czasowi życia stanowej sesji HTTP MCP. Naprawę bezpieczeństwa
należy oddzielić od migracji SDK i od korekty kontraktu on-prem. Bez testowego
ESET można wiarygodnie sprawdzić granice bezpieczeństwa i zgodność wysyłanych
żądań; nie można uczciwie potwierdzić pełnej zgodności z realnym backendem.

**Co potwierdzono i z jaką pewnością**

| ID | Ustalenie | Waga i warunki | Dowód / miejsce |
|---|---|---|---|
| S1 | Katalog RW zawiera `auth_o_auth__token` dla `/oauth/token`. | Wysoka wada granicy architektonicznej; nie jest dowodem skutecznego pobrania realnego tokena tym narzędziem. | `tools_loader.py:85`, `tools_loader.py:174`, test katalogu przez MCP. |
| S2 | Krótkie body błędu, zagnieżdżony wynik sukcesu i błąd composite mogą przenieść token do modelu. | Wysoka; wymaga pojawienia się sekretu w odpowiedzi/diagnostyce upstream. Testy celowo symulują taki upstream. | `errors.py:26`, `server.py:280`, `server.py:525`, `composite_tools.py:274`; trzy reprodukcje z fikcyjnym tokenem. |
| S3 | Dowolny poprawny składniowo Basic + własny `X-ESET-Server-URL` może skierować domyślny sekret CF na obcy host. | Krytyczna, jeżeli wspólny serwer ma sekret CF w env i caller może wskazywać host. Prawdziwe hasło ESET nie jest potrzebne do tej ścieżki. | `middleware.py:119`, `middleware.py:121`, `http_client.py:90`; mock niezatwierdzonego origin otrzymał sekret. |
| S4 | Sesja HTTP utworzona przez A przyjmuje żądanie z poświadczeniami B i wykonuje je nadal jako A. | Krytyczna przy współdzieleniu/ujawnieniu identyfikatora sesji; wysoka dla rotacji poświadczeń na istniejącym połączeniu. Nie dowodzi odgadywalności identyfikatorów. | `__main__.py:74`, `middleware.py:167`; rzeczywista aplikacja ASGI z managerem MCP, mock logowania ESET otrzymał login A przy nagłówku B. |
| S5 | Filtr logów usuwa wybrane klucze tylko na pierwszym poziomie. | Średnia; zagnieżdżone wartości zawierające sekrety przechodzą przez oba formatery. Tekst wiadomości i wyjątki też nie mają centralnej sanitacji — stwierdzenie z kodu. | `observability/logging.py:51`, `:80`, `:101`; dwa testy zagnieżdżonego pola. |
| F1 | 401 dla ważnego czasowo, ale unieważnionego tokena powtarza ten sam token. | Wysokie ryzyko niedostępności i błędów połączenia. | `auth.py:88`; reprodukcja: 0 odświeżeń, sekwencja `OLD → OLD`. |
| F2 | Przechwycony błąd ESET jest zwracany z `isError=false`. | Średnie; host/model może potraktować odmowę API jak sukces. | `server.py:280`; test 403 przez sesję MCP. |
| F3 | On-prem wysyła `grant_type: password`, ignoruje refresh token i deklaruje brak tego mechanizmu. | Wysokie ryzyko zgodności. Kod nie odpowiada obecnemu oficjalnemu schematowi; akceptacja aliasów przez konkretny serwer nie została sprawdzona. | `auth.py:192`, `auth.py:220`; niezależny test kontraktu 13.0. |
| F4 | Zależność `mcp>=1.2.0` dopuszcza niekompatybilną główną wersję. | Wysokie ryzyko przy świeżej instalacji. | `pyproject.toml`; w osobnym środowisku SDK 2.2.0: `build_server` kończy się `AttributeError: Server has no attribute list_tools`. |

W S1 występuje ważne ograniczenie: generator rozumie body JSON, a OAuth
wymaga formularza. W efekcie obecne narzędzie ma pusty schemat argumentów
i nie realizuje prawidłowego żądania OAuth. To przypadkowe ograniczenie,
nie zabezpieczenie: naprawienie formularzy bez usunięcia auth z katalogu
poszerzyłoby ekspozycję. RO ukrywa i blokuje ten tool — test to potwierdza —
ale nie zapobiega S2. Zasada „jedna operacja OpenAPI = jeden tool” z
`tests/test_catalog_vs_openapi.py` musi otrzymać jawne wyjątki bezpieczeństwa.

S4 wynika z dziedziczenia ContextVar przez zadanie tworzące sesję. Późniejsze
wiadomości trafiają do tego zadania i zachowują jego kontekst. Reset zmiennej
w middleware nie naprawia odziedziczonej kopii. Dotychczasowe testy sprawdzają
izolowane zadania i prosty endpoint ASGI, a nie to przejście przez manager MCP.
Dwa osobno zainicjalizowane połączenia A/B w nowym teście pozostają odizolowane.

Osobne ustalenie statyczne dotyczy wdrożenia: `eset-mcp-http` w
`docker-compose.yml` nie ma profilu i publikuje `8765:8765`. Polecenie opisane
dla produkcji, `docker compose --profile prod up -d`, obejmuje również tę
usługę, bo [usługi bez profilu są zawsze aktywne](https://docs.docker.com/compose/how-tos/profiles/).
Może więc pozostać wejście HTTP omijające Caddy; przy `env` jest to także
wejście bez uwierzytelnienia klienta MCP. Zależnie od firewalla jest to
ryzyko wysokie/krytyczne. Należy rozdzielić profile/compose i użyć jednoznacznej
nazwy backendu Caddy, obecnie współdzielonej z aliasem usługi prod. Nie
uruchamiano Dockera ani nie sprawdzano rzeczywistej dostępności portu.

**Porównanie API: zgodność historyczna a zgodność z producentem**

| Obszar | Obecna implementacja | Ocena i decyzja do planu |
|---|---|---|
| Cloud logowanie | POST do regionalnego `/oauth/token`, formularz, snake_case odpowiedzi. | Zgodne z publicznym kontraktem w sprawdzonym zakresie; pięć regionów przetestowanych syntetycznie, także znaki specjalne w haśle. |
| Cloud refresh | `grant_type=refresh_token`, ale brak kontrolowanego fallbacku po jego odrzuceniu; ważność access tokena wpływa na wybór refresh. | Osobne testy rotacji/wygaśnięcia/unieważnienia. Nie zmieniać sposobu logowania ESET tylko dlatego, że zmienia się MCP. |
| On-prem logowanie | POST `/GetTokens`, JSON, `grant_type: password`. | Oficjalny schemat 13.0 opisuje `grantType: PASSWORD`, `refreshToken`, `isDomainUser`; odpowiedź zawiera także `refreshToken`. Potrzebny kontrakt przypisany do wersji. |
| On-prem endpointy | Wszystkie specyfikacje cloud kierowane do jednego hosta; jeden override rename. | Publiczny katalog 13.0 opisuje znacznie mniejszy zestaw operacji. Brak wpisu nie dowodzi braku funkcji w każdej wersji, ale nie wolno zakładać równoważności całych API. |
| 202 | Powtórzenie metody/URL/query/body z `response-id`. | Podstawowa sekwencja zgodna i przetestowana. Brakuje odnowienia auth/obsługi 429 podczas pollingu oraz obsługi 202 z samego OAuth. |
| 429 | Backoff i liczbowy Retry-After. | Podstawowy przypadek przetestowany. Zaplanować limit całkowitego czasu, wartości ujemne/nieskończone, datę HTTP i przejście 429→401. |
| 5xx | Komentarz obiecuje jeden retry, kod od razu zwraca błąd. | Rozbieżność dokumentacji; retry zależny od idempotencji, bez automatycznego powtarzania zapisów o nieznanym wyniku. |

Źródła dla Cloud: [kontrakt OAuth](https://help.eset.com/eset_connect/en-US/authentication_oauth_token_post.html)
i [zasady 202](https://help.eset.com/eset_connect/en-US/how_api_works.html).
Źródła on-prem: [schemat GetTokens 13.0](https://help.eset.com/protect_admin/13.0/en-US/api_GetTokens_post.html)
i [katalog operacji 13.0](https://help.eset.com/protect_admin/13.0/en-US/api.html).
Strona [konfiguracji on-prem](https://help.eset.com/protect_admin/13.0/en-US/using_api.html)
używa małych liter w wartości `grantType`, a szczegółowy schemat — wielkich.
To dodatkowy powód, aby nie zmieniać requestów „na wyczucie” i nie maskować
niezgodności automatycznym wysyłaniem kilku wariantów logowania.

Utrwalono 101 narzędzi biznesowych, nazwy, skróty schematów wejścia i mapowanie
method/service/path/query/body. Testy przepuszczają każde przez mapper oraz
klienta HTTP w wariancie cloud i on-prem: 202 przypadki. To punkt odniesienia
do późniejszego porównania starej i nowej implementacji. Nie potwierdza
akceptacji payloadów przez ESET ani istnienia wszystkich ścieżek on-prem.
Usunięcie narzędzia uwierzytelniania jest celową zmianą bezpieczeństwa i zostało
wyłączone z kontraktu narzędzi biznesowych.

**Docelowa granica bezpieczeństwa**

```text
Klient MCP / host modelu
  → uwierzytelnienie klienta MCP
  → zweryfikowana tożsamość i uprawnienia do konkretnego profilu ESET
  → jawny, niezmienny AuthContext danego żądania
  → adapter Cloud albo On-Prem
  → menedżer tokenów → zatwierdzony origin API
  → bezpieczny wynik / bezpieczny błąd
  → wspólna kontrola poufności całej odpowiedzi MCP
  → model
```

Profil połączenia i sekrety są konfigurowane poza rozmową. Model nie wybiera
dowolnego origin, nie otrzymuje login-tool ani sekretu w `_meta`. Wspólny
serwer mapuje zweryfikowanego klienta na dozwolony profil; identyfikator profilu
ani sesji nie jest uwierzytelnieniem. Dla stdio dopuszczalny pozostaje lokalny
profil z env. Dla HTTP można zachować kontrolowany kontrakt z istniejącą
bramą jako etap przejściowy, z jednoznaczną granicą zaufania.

Docelowe OAuth dla HTTP MCP musi używać tokena przeznaczonego dla MCP,
sprawdzać issuer/audience/ważność/uprawnienia i oddzielać go od tokena ESET.
Nie przekazywać tokena klienta MCP do ESET. Wymagania te dotyczą warstwy
autoryzacji MCP, a nie przepisania wymaganego przez ESET password grant.
Custom auth jest osobnym wyborem wdrożeniowym; nie należy utożsamiać samej
migracji protokołu z koniecznością natychmiastowej wymiany całego logowania.
[Autoryzacja MCP](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).

Warstwa wyników powinna używać bezpiecznych typów błędów, jawnych kodów i
lokalnego identyfikatora korelacji. Raw body, pełne URL z userinfo/query,
niekontrolowany request-id i `str(exception)` nie powinny opuszczać adaptera.
Wyniki biznesowe wymagają polityki pól i rekurencyjnej kontroli także
`content`, `structuredContent`, resources, composite, logów i telemetrii.
Redakcja znanych wartości sekretów stanowi dodatkową ochronę. Sama lista
nazw kluczy lub regex nie daje ogólnej gwarancji dla dowolnego tekstu i
kodowań. Nie usuwać bezmyślnie `nextPageToken`: to kursor stronicowania,
którego semantykę należy zachować albo zastąpić nieprzenośnym uchwytem.

**Kolejność wdrożenia i kryteria akceptacji**

1. **Ustalić powtarzalny punkt odniesienia.** Zablokować niezamierzone przejście
   na SDK 2 przed migracją, wybrać wspieraną poprawkową wersję 1.x i utrwalić
   zależności. Zachować historyczne kontrakty; osobno zaznaczyć zatwierdzone
   zmiany bezpieczeństwa. Włączyć offline suite do CI, bez sekretów ESET.
   Warunek: instalacja i start na deklarowanych wersjach Pythona; jawny raport
   niewykonanych testów integracyjnych.
2. **Zamknąć granice sekretów i tenantów.** Usunąć auth z katalogu, resource
   katalogu i dispatchu, niezależnie od RO/RW. Zastąpić dowolny URL profilem
   zatwierdzonym dla klienta; powiązać sekret CF z jednym origin i odrzucać
   userinfo, zły port, hosty spoza profilu. Prywatne hosty on-prem dopuszczać
   jawnie, bo blanket blokada RFC1918 zepsułaby legalne wdrożenia. Dodać
   kontrolę DNS/egress i zachować zakaz redirectów. Przekazywać AuthContext
   jawnie do handlera; dla legacy odrzucać zmianę principal/profilu w sesji
   albo świadomie użyć wariantu bez stanu. Domknąć wspólną sanitację wyników,
   wyjątków i logów oraz odseparować produkcyjny ingress od dev HTTP.
   Warunek: brak wszystkich markerów sekretów na całym
   wyjściu MCP/logach oraz brak wywołań upstream po odrzuceniu żądania.
3. **Naprawić połączenia bez zmiany kontraktów biznesowych.** Dla 401 porównywać
   odrzucony token/generację pod lockiem, zamiast samego terminu ważności;
   jeden refresh na falę i najwyżej jedno ponowienie konkretnego requestu.
   Testować refresh-token rejection i kontrolowany fallback. Oddzielić
   adaptery cloud/on-prem oraz oficjalnie udokumentowane profile on-prem.
   Centralnie obsłużyć 202/429/401 z limitem czasu i poprawnym `isError`.
   Nie włączać niezweryfikowanych zapisów on-prem przez automatyczny fallback.
   Warunek: zgodność historyczna requestów poza jawną listą korekt oraz
   niezależna zgodność z przypiętym kontraktem producenta.
4. **Migrować warstwę MCP do SDK 2.x.** Zachować adaptery ESET z etapu 3,
   przebudować rejestrację handlerów i typy wyników, dodać testy starego i
   nowego klienta przez HTTP i stdio. Nie dokładać nieużywanych capabilities.
   Warunek: ta sama operacja biznesowa przez oba protokoły daje ten sam
   zatwierdzony request ESET; testy zgodności protokołu i poufności przechodzą.
5. **Wydanie etapowe.** Oddzielne zmiany/PR-y dla granic bezpieczeństwa,
   kontraktów API i migracji MCP. Na początek RO i jawna lista wspieranych
   operacji; RW pozostawić jako osobną decyzję wydaniową po walidacji.
   Przy braku testowego ESET oznaczyć ograniczenie walidacji. Przywracanie
   wersji ma prowadzić do poprawionej gałęzi bezpieczeństwa, nie do
   podatnego punktu wyjścia.

**Co zmienia MCP 2026-07-28**

Oficjalne [wydanie specyfikacji](https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28)
istnieje. Nie jest to zmiana etykiety. Nowy protokół usuwa sesje i handshake
`initialize`, wymaga `server/discover` oraz metadanych wersji i capabilities
w każdym żądaniu. Wyniki mają `resultType`; cacheable results potrzebują
`ttlMs` i `cacheScope`. HTTP dodaje `Mcp-Method`/`Mcp-Name`; subskrypcje mają
nową ścieżkę `subscriptions/listen`. Nie deklarować subskrypcji, jeśli serwer
ich nie implementuje. Dane zależne od konta powinny mieć prywatny cache,
początkowo z TTL=0; tenant nie może zostać wywnioskowany z połączenia.
Usunięcie wznowienia SSE wymaga szczególnej ostrożności przy ponawianiu
operacji RW po zerwaniu odpowiedzi. [Zmiany specyfikacji](https://modelcontextprotocol.io/specification/2026-07-28/changelog).

Oficjalny Python SDK 2.x obsługuje nową i starsze wersje protokołu.
[Wydania SDK](https://github.com/modelcontextprotocol/python-sdk/releases).
Sprawdzono lokalnie SDK 2.2.0 w oddzielnym środowisku: import obecnego modułu
jest możliwy, ale `build_server` nie działa, bo usunięto `Server.list_tools`.
Potrzebne są handlery `on_*`, jawne typy wyników i dostosowanie pól modeli
do snake_case oraz obsługi błędów. Zmieniają się również pomocniki testowe;
SDK używa `httpx2`, podczas gdy obecny adapter ESET może nadal używać
`httpx`. Nie migrować obu klientów HTTP przypadkowo w jednej zmianie.
Nową telemetrię OpenTelemetry należy objąć tą samą polityką poufności.
[Przewodnik migracji Python SDK](https://py.sdk.modelcontextprotocol.io/migration/).
Nie wykonano jeszcze testu zgodności działającego serwera z MCP 2026-07-28 —
serwer wymaga najpierw tej przebudowy.

**Pozostała macierz testów do implementacji**

| Warstwa | Przypadki wymagane przed wydaniem |
|---|---|
| Sekrety | Canaries w kluczach snake/camel/nested, tablicach, tekstach, błędach auth, nagłówkach i URL; różne długości body; JSON/text/composite/resource/structuredContent/_meta/logi/tracing; podstawowe kodowania; brak obchodzenia przez `fields` i limit bajtów. |
| Tożsamość | Brak/błędny auth; A→B w jednej sesji; zmiana hasła/CF/regionu/origin; różne uprawnienia; 100 równoległych wywołań; przerwanie; stary cache; wygasły/revoked token; session ID nie daje praw. |
| Egress | Nieznany host, userinfo, nietypowe porty, IPv6, DNS zmieniający adres, redirect; osobno zatwierdzony prywatny on-prem; zero nagłówków auth/CF dla niewłaściwego celu. |
| API | Każdy wspierany tool: poprawne typy i wartości wymaganych/opcjonalnych parametrów, path escaping i odrzucenie traversal, arrays/bools/Unicode, bodies; 204, błędny JSON, timeout, TLS i proxy; cloud we wszystkich regionach. |
| Retry | 401 dla ważnego/unieważnionego tokena, współbieżna fala 401, odrzucony refresh; 202→401/429/404/504; OAuth→202; 429→401; limit prób/czasu; zerwanie po wykonaniu POST bez ślepego retry. |
| Pool | Brak zamknięcia aktywnego klienta przy LRU eviction; poprawna identyfikacja profilu, CF client-id oraz parametrów TLS; ograniczenie zasobów i sprzątanie po anulowaniu. |
| MCP | 2025-11-25 i 2026-07-28 × HTTP/stdio × cloud/on-prem × RO/RW; discover, błędna wersja, headers/body mismatch, prywatny cache, isError, deterministyczny katalog, rozłączenie, weryfikacja rzeczywistego klienta docelowego. |

**Ryzyko braku pokrycia**

| Obszar | Ryzyko teraz | Ryzyko po wykonaniu planu, nadal bez testowego ESET |
|---|---|---|
| Przepływ sekretów kontrolowanych przez serwer | Wysokie/krytyczne, reprodukcje istnieją. | Niskie–średnie dla sprawdzonych granic; nowe pola, dowolny tekst i kodowania nadal wymagają kontroli. |
| Izolacja tenantów | Krytyczne przy reuse/wycieku sesji. | Niskie–średnie po jawnej tożsamości i pełnych testach transportowych; konfiguracja bramy pozostaje osobnym ryzykiem. |
| Cloud: method/URL/headers/body | Częściowo sprawdzone; problem 401. | Niskie dla porównania requestów; średnie dla zachowania żywego API, uprawnień, licencji i limitów. |
| On-prem: wersje i możliwości | Wysokie: rozbieżny auth i katalog cloud jako fallback. | Średnie–wysokie do testu na konkretnej wersji; mock nie potwierdzi nieudokumentowanych aliasów i endpointów. |
| Operacje RW | Wysokie: brak realnej walidacji skutków. | Wysokie dla skutków i idempotencji bez canary; offline można sprawdzić dokładny request i zakaz niedozwolonego retry. |
| MCP/host klienta/proxy | Wysokie dla niekontrolowanego SDK bump. | Średnie po testach obu wersji; zachowanie rzeczywistego klienta, SSE, TLS i reverse proxy wymaga osobnej próby. |

Nie ma podstaw do liczbowej obietnicy typu „99% bezpieczeństwa” ani do
utożsamiania liczby testów z pokryciem zachowania. Bez środowiska testowego
nie można zweryfikować realnych Permission Sets, licencji, zakresu danych,
łańcucha certyfikatów, CF Access, limitów obciążenia ani wykonania poleceń RW.
Dlatego dwa niezależne porównania — historyczne requesty i kontrakt producenta
— są obowiązkowe, ale nadal nie zastępują integracji.

**Wynik wykonanej walidacji**

- Dotychczasowe testy offline: **137 passed**; testy zależne od konta nieuruchomione.
- Nowy pakiet: **212 passed, 12 xfailed**. Po `--runxfail`: **212 passed,
  12 failed** — to potwierdzone niespełnione wymagania, a nie zielony audyt.
- Ruff dla nowego pakietu: bez błędów.
- SDK 2.2.0: potwierdzona niezgodność inicjalizacji obecnego serwera;
  migracji produkcyjnej nie wykonano.
- Środowisko: Python 3.14.6; baseline MCP 1.27.1, HTTPX 0.28.1, Starlette 1.0.0.
  Python 3.11–3.13 oraz realne TCP/TLS/proxy nie były częścią uruchomienia.

Instrukcje odtworzenia: `audits/README.md`. Wyniki: `audits/baseline-results.txt`.
Każdy sekret w reprodukcjach jest syntetyczny. Testy audytu blokują DNS
i rzeczywiste połączenia sieciowe; nie używano poświadczeń z `.env`.
