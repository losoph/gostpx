# Командная строка

Тот же бинарь, что и приложение. Без аргументов запускает трей, с аргументами —
работает как обычная утилита и завершается. GUI для управления не требуется:
всё, что делает меню, делает и CLI.

В режиме `sysproxy` CLI управляет сессией напрямую (через `state.json` и
системные настройки ОС) без демона ([ADR-016](DECISIONS.md#adr-016)). В будущем
режиме `tun` (Phase 3, отложено) команды будут взаимодействовать с демоном по IPC.

---

## Управление соединением

```bash
gostpx on                  # подключиться (держит сессию до Ctrl+C)
gostpx off                 # отключиться
gostpx toggle              # переключить — то, что делает клик в меню
gostpx mode sysproxy       # tun | sysproxy | off
```

## Состояние

`status` печатает не только факт подключения, но и **охват** — что этим
режимом ловится, а что идёт мимо. Строки с `⚠` не ошибки, а честное описание,
и они не должны исчезать «чтобы не пугать» ([LIMITATIONS.md](LIMITATIONS.md)).

```bash
gostpx status              # человекочитаемо (только кэш, без сетевых запросов)
gostpx status --json       # для скриптов
gostpx status --check-ip   # дополнительно узнать внешний IP и страну (сетевой запрос)
```

```
$ gostpx status
● подключено      socks5  proxy.example.net:8000   режим: tun   42 ms
  охват           IPv4 TCP/UDP всех процессов, DNS через DoH
  ⚠ IPv6          активен в сети — идёт напрямую, мимо прокси
  сессия          17 мин
```

```
$ gostpx status --check-ip
● подключено      socks5  proxy.example.net:8000   режим: sysproxy   42 ms
  охват           Safari/Chrome/Edge, системные приложения
  ⚠ консоль       curl, git, pip идут напрямую — задай ALL_PROXY
  ⚠ DNS           резолвит система, DoH браузера может идти мимо
  ⚠ UDP / QUIC    идёт напрямую (sysproxy перехватывает только TCP)
  внешний IP      192.0.2.50 (US)
  сессия          17 мин
```

```
$ gostpx status --check-ip --json
{"state":"connected","mode":"sysproxy","proxy":"socks5://proxy.example.net:8000",
 "rtt_ms":42,"uptime_s":1020,"external_ip":"192.0.2.50","external_country":"US",
 "coverage":{"ipv4":false,"ipv6":false,"dns":"system","console":false},
 "warnings":["console_direct","udp_quic_direct","doh_not_applicable"]}
```

При обрыве состояние меняется немедленно, не дожидаясь очередной проверки:

```
$ gostpx status
○ прямое подключение        причина: proxy unreachable (connection refused)
  ⚠ весь трафик идёт мимо прокси, с реальным IP
```

## Конфиг

```bash
gostpx config path                # путь к config.toml
gostpx config edit                # открыть в редакторе
gostpx config validate            # проверить, не применяя
gostpx config show                # эффективный конфиг после дефолтов
gostpx config reload              # перечитать принудительно
```

`edit` выбирает редактор в порядке: `$VISUAL` → `$EDITOR` → `open -t` на
macOS → `notepad` на Windows. После закрытия редактора конфиг автоматически
валидируется, и при ошибке предлагается вернуться к правке.

## Прокси и DNS

Профиль один, поэтому вместо списка — две команды:

```bash
gostpx set socks5://user:pass@proxy.example.net:8000
gostpx set --show                 # что сейчас настроено (без пароля)
gostpx test                       # проверить доступность, не переключаясь

gostpx dns https://dns.google/dns-query
gostpx dns --show
```

`set` вычищает пароль из строки и кладёт его в `credentials.toml` рядом
с конфигом (права `0600`, [ADR-011](DECISIONS.md#adr-011)); URL без пароля
этот файл удаляет. `dns` применяется только к режиму `tun` — в `sysproxy`
имена резолвит сам прокси-сервер, и команда об этом предупреждает.

## Окружение шелла

Консольные программы (`curl`, `git`, `npm`, `go`) системный прокси не
читают, им нужны переменные окружения ([LIMITATIONS.md](LIMITATIONS.md)).
`env` печатает их для `eval`; сам gostpx в rc-файлы, `launchctl setenv`
и `setx` не пишет ([ADR-017](DECISIONS.md#adr-017)).

```bash
eval "$(gostpx env)"              # прокси для текущего шелла
eval "$(gostpx env --unset)"      # снять
gostpx env --shell powershell     # синтаксис PowerShell ($env:...)
```

```
$ gostpx env
export HTTP_PROXY=http://127.0.0.1:8080 http_proxy=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080
export ALL_PROXY=socks5h://127.0.0.1:1080 all_proxy=socks5h://127.0.0.1:1080
export NO_PROXY=localhost,127.0.0.1,::1 no_proxy=localhost,127.0.0.1,::1
```

Адреса берутся из `[sysproxy]` конфига; `socks5h` — имя резолвит прокси.
`NO_PROXY` обязателен: без него клиенты шлют в прокси и запросы к своим
локальным сервисам ([ADR-019](DECISIONS.md#adr-019)). Команда не требует
активной сессии и ничего не проверяет по сети; если сессия не активна,
строки всё равно печатаются, а в stderr уходит предупреждение.

## Работа совсем без GUI

В текущей версии (режим `sysproxy`) всё управление доступно через CLI:

```bash
gostpx set socks5://user:pass@proxy.example.net:1080  # настроить прокси
gostpx on                                             # включить и держать сессию
eval "$(gostpx env)"                                  # настроить текущий шелл (curl, git)
gostpx status                                         # проверить статус
gostpx off                                            # отключить прокси
```

В режиме `sysproxy` для перехвата консольных программ используется `gostpx env`.
В будущем режиме `tun` (Phase 3) трафик консоли пойдёт через виртуальный интерфейс автоматически.

---

## Запланировано (Phase 3+)

Следующие команды запланированы для режима `tun` и расширенной диагностики:

### Демон (`gostpxd`, запланировано)

```bash
gostpxd install                   # поставить службу/LaunchDaemon (запросит пароль)
gostpxd uninstall
gostpxd status
gostpxd run --foreground          # для отладки
```

### Логи и диагностика (запланировано)

```bash
gostpx logs                       # последние строки
gostpx logs -f                    # следить
gostpx logs --level debug
gostpx doctor --connections [--json] # снимок соединений процессов мимо прокси
gostpx doctor --bundle report.zip # собрать всё для разбора проблемы
```

`doctor` проверяет: жив ли демон и отвечает ли, поднят ли TUN-интерфейс, стоит
ли pin-route до прокси, не остался ли системный прокси от прошлой сессии, есть
ли в сети рабочий IPv6 и не поднят ли второй VPN, перехвативший default route.

## Коды возврата

| Код | Значение |
|---|---|
| 0 | успех |
| 1 | общая ошибка |
| 2 | ошибка в конфиге (валидация не прошла) |
| 3 | демон недоступен или не установлен |
| 4 | недостаточно прав |
| 5 | не удалось подключиться к апстриму |

Отдельные коды нужны, чтобы `gostpx on || ...` в скриптах различал
«прокси лежит» и «конфиг сломан».
