# BGP Route Fetcher

Утилита получает IPv4-маршруты из RADB WHOIS по списку origin AS, при необходимости суммаризирует их и анонсирует в FRRouting через `vtysh`.

## Возможности

- читает конфигурацию из `config.yaml`;
- параллельно запрашивает маршруты из `whois.radb.net`;
- валидирует, дедуплицирует и сортирует только IPv4-сети;
- по умолчанию суммаризирует маршруты через `ipaddress.collapse_addresses()`;
- поддерживает режим без суммаризации через `-nosum` / `--no-summarize`;
- анонсирует сети в FRR батчами;
- опционально отзывает устаревшие маршруты через `--withdraw`;
- завершает выполнение с ошибкой, если часть батчей не была анонсирована.

## Требования

- Python 3.9+
- `whois`
- `vtysh` из FRRouting для реального анонса
- Python-зависимости:

```bash
python3 -m pip install pyyaml loguru
```

## Быстрый старт

Создайте и при необходимости отредактируйте `config.yaml`, затем выполните безопасную проверку:

```bash
python3 getroutes.py --dry-run
```

Если результат устраивает, можно запускать обычный режим:

```bash
python3 getroutes.py
```

## Структура проекта

- `getroutes.py` - основной CLI-скрипт: загрузка конфига, WHOIS-fetching, нормализация, суммаризация, announce/withdraw;
- `config.yaml` - рабочая конфигурация роутера и списка сервисов;
- `tests/test_getroutes.py` - unit-тесты для чистых функций и отдельных helper'ов;
- `AGENTS.md` - инженерные правила и команды проверки для локальной разработки.

## Конфигурация

Пример `config.yaml`:

```yaml
router:
  as_number: 65001
  log_file: "logs/routes.log"

  # Fetching behaviour
  fetch_workers: 8
  whois_concurrency: 4
  fetch_retries: 3
  retry_delay_sec: 0.5
  whois_timeout_sec: 30
  total_timeout_sec: 600

  # Announcement behaviour
  batch_size: 500
  announce_timeout_sec: 120

  services:
    youtube:
      as_numbers:
        - 36561
        - 15169
```

### Параметры `router`

- `as_number` - локальный BGP AS для `router bgp`
- `log_file` - путь к файлу лога
- `fetch_workers` - число worker-потоков для задач получения маршрутов
- `whois_concurrency` - лимит одновременных WHOIS-запросов
- `fetch_retries` - число повторных попыток для одного ASN
- `retry_delay_sec` - базовая задержка между повторами
- `whois_timeout_sec` - таймаут одного вызова `whois`
- `total_timeout_sec` - общий таймаут выполнения скрипта
- `batch_size` - сколько сетей отправлять в один вызов `vtysh`
- `announce_timeout_sec` - таймаут одного batched-анонса
- `services` - набор сервисов и списков `as_numbers`

### Параметры `services`

Каждый сервис описывается так:

```yaml
services:
  cloudflare:
    as_numbers:
      - 13335
```

- имя сервиса используется только для логов и удобства чтения конфига;
- `as_numbers` должен быть непустым списком положительных ASN;
- хотя бы один сервис должен быть задан.

## Использование

Обычный запуск:

```bash
python3 getroutes.py
```

С альтернативным конфигом:

```bash
python3 getroutes.py --config /path/to/config.yaml
```

Без суммаризации:

```bash
python3 getroutes.py -nosum
```

или:

```bash
python3 getroutes.py --no-summarize
```

Без реального вызова `vtysh`:

```bash
python3 getroutes.py --dry-run
```

С отзывом устаревших маршрутов (сравнивает текущие анонсы FRR с результатами RADB):

```bash
python3 getroutes.py --withdraw
```

Комбинация dry-run и отключенной суммаризации:

```bash
python3 getroutes.py --dry-run -nosum
```

## Как работает скрипт

1. Загружает и валидирует YAML-конфиг.
2. Проверяет наличие `whois`, а для не-`dry-run` режима и `vtysh`.
3. Параллельно получает `route:` записи из RADB WHOIS для всех ASN.
4. Оставляет только валидные IPv4-сети.
5. Либо суммаризирует сети, либо оставляет их как есть при `-nosum`.
6. В обычном режиме отправляет батчи команд `network ...` в FRR.
7. При `--withdraw` читает текущие анонсы через `show bgp ipv4 unicast` и удаляет маршруты, которых больше нет в RADB.

## Поведение

- В анонс попадают только валидные IPv4-сети.
- IPv6 и невалидные записи пропускаются с логированием.
- Ранние логи пишутся в stderr, после загрузки конфига включается файл лога.
- При частично неуспешном анонсе скрипт завершается с кодом ошибки.
- `--dry-run` пропускает вызов `vtysh`, но не пропускает загрузку конфига и WHOIS-fetching.

## Эксплуатационные замечания

- Перед реальным запуском рекомендуется использовать `--dry-run`, особенно после изменения `config.yaml`.
- Один и тот же ASN может встречаться в нескольких сервисах; итоговые маршруты дедуплицируются после сбора.
- При `--withdraw` скрипт сравнивает текущие анонсы FRR с новым набором маршрутов и удаляет лишние префиксы, поэтому этот режим лучше использовать только при стабильном доступе к WHOIS и после предварительной dry-run проверки.
- Для больших списков ASN основными ручками настройки являются `whois_concurrency`, `fetch_retries`, `whois_timeout_sec` и `batch_size`.

## Разработка и проверка

Легкая проверка синтаксиса:

```bash
python3 -m py_compile getroutes.py
```

Тесты (чистые функции, не требуют `whois` / `vtysh`):

```bash
python3 -m pytest tests/test_getroutes.py -v
python3 -m pytest tests/test_getroutes.py -k normalize
```

Рекомендуемая безопасная проверка поведения:

```bash
python3 getroutes.py --dry-run
```

Если зависимостей или системных команд нет, сначала установите их.

## Типовые проблемы

- `Required command 'whois' is not available in PATH` - установите WHOIS-клиент.
- `Required command 'vtysh' is not available in PATH` - установите FRRouting или поправьте `PATH`.
- `permission denied` при `vtysh` - дайте пользователю доступ к FRR.
- таймауты WHOIS - уменьшите `whois_concurrency`, увеличьте `fetch_retries` или `whois_timeout_sec`.
- пустой результат - проверьте, что у указанных ASN есть `route:` записи в RADB.

## Ограничения

- Скрипт работает только с IPv4-маршрутами.
- Без `--withdraw` скрипт только добавляет маршруты; устаревшие анонсы остаются в FRR.
- Линтер в репозитории не настроен.
- Проект пока остается single-file utility; явной package-структуры и отдельного dependency management файла нет.
