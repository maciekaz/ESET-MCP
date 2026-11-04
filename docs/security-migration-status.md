# Bezpieczeństwo i MCP 2026-07-28 — wykonanie planu

Stan walidacji: 2026-11-04, kandydat lokalny 1.1.0, przygotowany do wydania jako
**2.0.0** ze względu na breaking changes konfiguracji. Dotyczy Cloud i On-Prem.
Instrukcja publicznej aktualizacji: [migracja v1 → v2](migration-v2.md).
Punkt odniesienia: commit `442dcadadcfde802cf0b7ccb1955438ed20fcf15` (1.0.3),
SDK MCP 1.27.1. Wdrożono poprawki w kodzie i konfiguracji repozytorium;
nie wykonano wdrożenia do ESET ani publikacji obrazu.

## Zachowana funkcjonalność

Zachowano **101 narzędzi biznesowych, ich nazwy, schematy wejściowe, mapowania
metod/URL/query/body oraz cztery narzędzia złożone**. Cloud nadal obsługuje pięć
regionów. RO udostępnia 51 narzędzi, RW — 105. Pozostają zasoby, prompty,
paginacja, projekcja `fields`, ograniczenie odpowiedzi i historyczne ścieżki
On-Prem. Nie wyłączono RW ani historycznych endpointów ze względu na brak
środowiska testowego. Ich dostępność na konkretnej konsoli nadal zależy od ESET.

Jedynym usuniętym narzędziem jest `auth_o_auth__token`: pobieranie tokenów jest
wewnętrzną funkcją adaptera, nie operacją dla modelu. Nie zmieniono plików
OpenAPI ani historycznego snapshotu schematów biznesowych.

Domyślny login On-Prem nadal wysyła historyczne JSON
`grant_type: "password"`. Jawny `ESET_ONPREM_AUTH_STYLE=v13` korzysta z
udokumentowanego `grantType: "PASSWORD"` / `"REFRESH_TOKEN"`. Nie ma zgadywania
wersji konsoli ani automatycznej zmiany dialektu po błędzie. Schemat ESET 13
sprawdzono niezależnie od starego kodu; rzeczywistej konsoli nie testowano.
[Kontrakt GetTokens ESET 13](https://help.eset.com/protect_admin/13.0/en-US/api_GetTokens_post.html).

## Wprowadzone zabezpieczenia

1. **Granica modelu.** Wspólna sanitacja wyników zwykłych i złożonych narzędzi
   usuwa znane wartości poświadczeń/tokenów oraz poufne klucze zagnieżdżone w
   JSON. Obejmuje typowe kodowania i tekstowe kopie JSON. Działa przed `fields`
   i limitem bajtów. Kursory paginacji zostają. Błędy nie przechowują ani nie
   oddają surowych body, URL i request-id upstream; używają lokalnej korelacji.
   Faktyczne błędy mają `isError=true`, także po ograniczeniu wielkości wyniku.
2. **Tożsamość żądania.** Handler korzysta z jawnego obiektu HTTP przekazanego
   przez SDK, nie z kontekstu odziedziczonego przez zadanie sesji. Stara sesja
   jest powiązana z hashem pełnej tożsamości połączenia; zmiana hasła, regionu,
   originu lub pary CF wymaga ponownego połączenia. Nowy protokół jest bezstanowy.
   Zduplikowane nagłówki poświadczeń/routingu są odrzucane.
3. **Cel połączenia.** Dodatkowy origin On-Prem wymaga listy dopuszczeń dla
   konkretnego użytkownika. Domyślna para CF nie trafia do innego originu.
   DNS jest sprawdzany przy połączeniu TCP, a sprawdzony IP zostaje przypięty;
   Host, SNI i walidacja certyfikatu nadal używają właściwej nazwy konsoli.
   Domyślnie blokowane są adresy specjalne; prywatne sieci On-Prem są dozwolone.
   Wyłączono redirecty i automatyczne proxy z otoczenia procesu.
4. **Tokeny i ponowienia.** 401 wymienia również niewygasły, odrzucony token.
   Lock porównuje odrzuconą wartość, dzięki czemu równoległe żądania współdzielą
   jedno udane odnowienie. Refresh działa także po wygaśnięciu access tokena;
   jawne `invalid_grant` pozwala na jednorazowy powrót do hasła. Brak nowego
   refresh tokena w poprawnej odpowiedzi nie kasuje poprzedniego. Wspólna obsługa
   auth/API obejmuje 202, 429, 401 i limit czasu. Metoda, query i body pollingu
   nie zmieniają się; 5xx i awarie transportu nie powtarzają zapisów w ciemno.
5. **Cykl życia klienta.** Lease chroni aktywne wywołanie, w tym fan-out
   composite, przed zamknięciem klienta przez LRU. Zwolnienie i anulowanie
   sprzątają klienta wycofanego z cache. Klucz uwzględnia również CF client-id,
   ustawienia TLS, CA, sieci i profil auth.
6. **Logi i wdrożenie.** Sanitacja obejmuje tekst, wyjątki i zagnieżdżone pola.
   Wyłączono surowe logi HTTP. Caddy filtruje nagłówki/URI także w logach błędów,
   dostaje tylko publiczne zmienne konfiguracji i nie wystawia metryk.
   Profil prod uruchamia tylko Caddy i wewnętrzny MCP; profile lokalne są jawne
   i publikują port tylko na loopback. Kontekst budowy Dockera jest listą
   dozwolonych plików. [Filtrowanie logów Caddy](https://caddyserver.com/docs/caddyfile/directives/log#filter).

Cloud zachowuje formularz OAuth i regionalne domeny; 202 zachowuje oryginalne
żądanie z `response-id`, zgodnie z dokumentacją producenta.
[Cloud OAuth](https://help.eset.com/eset_connect/en-US/authentication_oauth_token_post.html),
[polling ESET](https://help.eset.com/eset_connect/en-US/how_api_works.html).

## Zakres migracji MCP

Przypięto `mcp==2.3.0`, pozostawiając adapter ESET na osobno przypiętym HTTPX
0.28.1 / HTTPCore 1.0.9. SDK 2 używa własnego HTTPX2. Produkcyjne i testowe
zależności mają lockfile z hashami. Handlery korzystają z `on_*` i jawnych typów
wyników. Sprawdzono `server/discover`, metadane każdego żądania, zgodność
nagłówków z body, błędną wersję, `resultType`, prywatny cache z TTL=0 oraz
starszy handshake. Serwer nie deklaruje niezaimplementowanych subskrypcji.
[Specyfikacja 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28),
[HTTP i zgodność wsteczna](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http),
[migracja SDK](https://py.sdk.modelcontextprotocol.io/migration/).

**To obsługa bazowego protokołu i transportów MCP, nie implementacja profilu
OAuth 2.1 MCP.** Zachowano dotychczasowy własny Basic ingress. Klient musi umieć
ustawić nagłówki; klient wymagający wyłącznie discovery OAuth potrzebuje
oddzielnej warstwy autoryzacji. Token ESET nigdy nie jest tokenem Bearer ingressu
MCP. Ta granica jest celowa i nie jest deklaracją pełnej zgodności OAuth.
[Autoryzacja MCP](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).

## Podwójna walidacja i dowody

- Końcowa macierz: **525 passed, 8 skipped na każdym z Pythonów 3.11, 3.12,
  3.13 i 3.14**. Pokrycie instrukcji i gałęzi łącznie: **87%**;
  moduł sanitacji sekretów: **100%**, obsługa tokenów: **99%**.
- Ponownie uruchomiona, odizolowana stara implementacja: **349 passed,
  12 xfailed**. Wszystkie 12 reprodukcji jest obecnie zwykłymi testami
  wymagającymi powodzenia; nie pozostawiono maskujących xfail.
- Pierwszy wzorzec: niezmieniony `legacy_business_contract.json`, 101 nazw
  i hashy schematów oraz **202 porównania mapper + HTTP** (oba backendy).
- Drugi wzorzec: `legacy_execution.json` pochodzi z rzeczywistego wykonania
  starego serwera/SDK przy syntetycznym upstream. Nowy serwer porównano przez
  niezależne surowe żądania HTTP: **404 wywołania biznesowe + 16 wywołań
  composite**, obejmujące również poprawne typy wejść, paginację, sortowanie
  i limity fan-out. Zgodne są żądania API i zwykła treść wyników.
- Niezależne kontrakty producenta: pięć regionów Cloud, kodowanie formularza,
  jawny profil On-Prem v13, login/refresh, odpowiedzi 202 i `response-id`.
  Nie zastąpiono nimi historycznych oczekiwań ani nie pobierano nowych OpenAPI
  zmieniających katalog.
- Dodatkowe przypadki: canaries w sukcesach/błędach/logach, cache tokenów,
  projekcja i cap, błędne schematy i path traversal, niedozwolony origin,
  DNS/IP, rotacja tożsamości sesji, 40 równoległych tenantów na każdą erę,
  fala 50 odnowień, anulowanie i eviction, 202→401→429, brak replay zapisów,
  niepoprawny JSON, redirect, timeout oraz częściowa awaria composite.
- Prawdziwe lokalne TCP/TLS sprawdzają Host/SNI, CA, weryfikację i jej jawne
  wyłączenie, CF headers, profile auth oraz odmowę przed przesłaniem sekretów.
- CLI działa w osobnych procesach przez JSON-lines: obie ery × dwa backendy
  × RO/RW. Oddzielny rzeczywisty klient SDK 1.27.1 sprawdził nowy serwer stdio;
  klient SDK 2 sprawdził HTTP obu er i przekierowanie końcowego slash.
- Oficjalny Caddy 2.11.7, pobrany i zweryfikowany SHA-256: parser rzeczywistego
  Caddyfile oraz lokalna próba 502 potwierdziły filtrowanie sekretów w logu
  błędu i publiczne 404 dla metryk. Brak domeny uniemożliwia start Caddy;
  lokalne profile Compose działają bez zmiennych konfiguracji publicznej.
  TLS/ACME produkcyjnego proxy nie uruchamiano.
- Wheel i sdist 1.1.0 zbudowano; wheel zawiera wszystkie 17 plików JSON OpenAPI
  i overrides. Archiwa nie zawierają `.env`, `.git` ani niepowiązanych katalogów.
  Gotowy wheel zainstalowano w czystym środowisku z zależnościami produkcyjnymi:
  import i katalog 105 narzędzi działają bez checkoutu w ścieżce importów.
  Ruff i `git diff --check` przechodzą.
- Po uruchomieniu Dockera zbudowano obrazy **linux/arm64 i linux/amd64**.
  Na każdym przeszły **24 scenariusze CLI** (stdio/HTTP × legacy/modern ×
  Cloud/On-Prem legacy/On-Prem v13 × RO/RW) i **300 dodatkowych odczytów**
  w seriach po 10 równoległych żądań. To rzeczywiste połączenia TLS do
  syntetycznego API, z kontrolą Host/SNI, CA, CF, treści żądań, sanitacji
  wyników i logów. Kod aplikacji w obrazie nie był podmieniany. Kontenery
  działały jako UID 10001, z read-only filesystem i `--network none`.
  ARM64 sprawdzono natywnie, AMD64 w emulacji Docker Desktop.
- Pełna regresja na obrazie Linux ARM64 z dodaną warstwą zależności testowych:
  **525 passed, 8 skipped**. Osobno sprawdzono właściwy ENTRYPOINT obrazu
  produkcyjnego w stdio i HTTP, bramkę Basic Auth i kontrolowane zatrzymanie;
  kontener testowy nie miał restartów ani OOM. Test TLS obrazu dodano do CI.

Końcowe wyniki interpreterów i pokrycia znajdują się w
[`audits/validation-python311.txt`](../audits/validation-python311.txt),
[`312`](../audits/validation-python312.txt),
[`313`](../audits/validation-python313.txt),
[`314`](../audits/validation-python314.txt) oraz
[`coverage-summary.txt`](../audits/coverage-summary.txt).
Pokrycie nie scala subprocessów CLI; procent nie oznacza prawdopodobieństwa
bezpieczeństwa. Testy realnego ESET są wyłączone: część jest pomijana, część
nie jest kolekcjonowana. Żadne prawdziwe konto ani `.env` nie były używane.
Instrukcje odtworzenia: [`audits/README.md`](../audits/README.md).

Dowody kontenerowe: [`ARM64`](../audits/validation-docker-arm64.txt),
[`AMD64`](../audits/validation-docker-amd64.txt),
[`regresja Linux`](../audits/validation-docker-regression.txt),
[`ENTRYPOINT`](../audits/validation-docker-entrypoint.txt),
[`identyfikatory obrazów`](../audits/validation-docker-images.json).
Obraz lokalny: `eset-mcp:1.1.0-local` (ARM64); drugi wariant:
`eset-mcp:1.1.0-amd64-check`. Nie opublikowano ich do rejestru.
W chwili sprawdzenia istniejący kontener `eset-mcp-http` nadal korzystał
z osobnego obrazu `eset-mcp-eset-mcp-http`, pakietu **0.1.0** i SDK **1.27.1**;
budowa nowego obrazu nie aktualizowała tej działającej usługi.

## Ustawienia wymagające uwagi przy aktualizacji

| Ustawienie / zachowanie | Co skonfigurować |
|---|---|
| `ESET_MCP_ALLOWED_HOSTS` | Publiczny Host reverse proxy. Compose prod ustawia go na `ESET_PUBLIC_DOMAIN`. Dla nietypowych portów można podać `host:*`. |
| `ESET_MCP_ALLOWED_ORIGINS` | Tylko wymagane originy klientów przeglądarkowych. Klient bez Origin nie wymaga wpisu. |
| `ESET_ONPREM_ORIGINS` | JSON `{"użytkownik":["https://konsola:9443"]}` dla dodatkowych originów. Skonfigurowany origin domyślny pozostaje dozwolony. |
| Para CF w środowisku | Działa wyłącznie dla domyślnej konsoli. Inny dozwolony origin wymaga własnej pary nagłówków, jeśli korzysta z Access. |
| `ESET_ONPREM_NETWORKS` | Opcjonalne CIDR ograniczające połączenia. Loopback/link-local wymagają jawnej zgody w tej konfiguracji. |
| `ESET_CA_BUNDLE` | Plik PEM z zaufanym CA. `SSL_CERT_FILE` i automatyczne proxy środowiskowe nie są używane. |
| `ESET_ONPREM_AUTH_STYLE` | Pozostawić `legacy` dla zachowania dotychczasowego logowania; `v13` włączyć dla świadomie wybranego kontraktu. |
| Env-auth HTTP na `0.0.0.0` | Domyślnie odrzucone. Jawny override tylko za niezależnie uwierzytelnioną bramą. Profile Compose HTTP korzystają z Basic. |
| Rotacja hasła/CF/regionu/originu | Nowa sesja dla klienta legacy. Klient modern przesyła tożsamość w każdym żądaniu. |
| Docker Compose | `--profile http` / `--profile prod` / `--profile stdio`, z `--build`. Obraz lokalny powstaje z poprawionego checkoutu; stary opublikowany tag nie uzyskuje tych zmian automatycznie. |

## Ryzyko pozostałe bez środowiska ESET

| Obszar | Ocena po zmianach | Czego testy nie dowodzą |
|---|---|---|
| Sekrety i izolacja tenantów | Niskie–średnie dla sprawdzonych granic | Braku dowolnych nowych kodowań, nieznanych pól, błędnej konfiguracji zewnętrznych loggerów/tracingu ani odczytu pamięci procesu. |
| Requesty Cloud | Niskie dla zgodności historycznej; średnie integracyjnie | Aktualnych uprawnień, licencji, limitów i akceptacji każdego body przez usługę. |
| On-Prem | Średnie–wysokie | Obsługi historycznych aliasów, wariantu v13 i modułów na konkretnej wersji konsoli. Zachowany fallback ścieżek Cloud nie oznacza ich dostępności On-Prem. |
| Operacje RW | Wysokie dla rzeczywistych skutków | Wykonania akcji, atomowości i idempotencji ESET. Po timeout/rozłączeniu należy ustalić stan przed ręcznym ponowieniem. |
| Klient MCP i produkcyjna sieć | Średnie | Zachowania konkretnego hosta użytkownika, realnego CF Access, SSO, proxy, łańcucha certyfikatów i długich strumieni pod obciążeniem. |
| Obraz kontenera | Niskie–średnie po build i próbach runtime | Zbudowano i przetestowano ARM64 oraz emulowany AMD64. Nie wykonano długiego testu obciążenia, natywnego testu AMD64, produkcyjnego ACME/CF ani całego stosu Compose z rzeczywistym ESET. Zdalnego CI jeszcze nie wykonano. |

Te ograniczenia odpowiadają zaakceptowanemu brakowi środowiska testowego.
Nie ma podstaw do deklaracji „pełnego bezpieczeństwa” ani potwierdzenia
produkcyjnych efektów RW. Kod i dowody offline są gotowe do przeglądu;
wdrożenie powinno uwzględnić powyższe jawne zmiany konfiguracji. Powrót do
niepoprawionej 1.0.3 przywraca odtworzone podatności; zachować artefakt poprawionej
wersji jako punkt dalszych poprawek kompatybilności.
