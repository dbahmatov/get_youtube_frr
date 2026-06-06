# BGP Route Fetcher

Утилита получает IPv4-маршруты из RADB WHOIS по списку origin AS, суммаризирует их и анонсирует в FRRouting через `vtysh`.

## Возможности

- параллельный запрос маршрутов из `whois.radb.net`;
- фильтрация только IPv4-сетей с валидацией;
- автоматическая суммаризация маршрутов;
- анонс сетей в FRR батчами;
- отзыв устаревших маршрутов через `--withdraw`.

## Требования

- Python 3.9+
- `whois`
- `vtysh` из FRRouting
- Python-зависимости:

```bash
python3 -m pip install pyyaml loguru
```

## Использование

Создайте `config.yaml` и при необходимости отредактируйте его.

Безопасная проверка (без вызова `vtysh`):

```bash
python3 getroutes.py --dry-run
```

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

Отзыв устаревших маршрутов:

```bash
python3 getroutes.py --withdraw
```

## Конфигурация

Пример `config.yaml`:

```yaml
router:
  as_number: 65001
  log_file: "logs/routes.log"
  services:
    youtube:
      as_numbers:
        - 36561
        - 15169
```

### Параметры `router`

- `as_number` — локальный BGP AS для `router bgp`
- `log_file` — путь к файлу лога
- `services` — набор сервисов и списков `as_numbers`

Каждый сервис описывается именем и непустым списком ASN. Имя используется только для логов.

## Эксплуатационные замечания

- Перед реальным запуском рекомендуется использовать `--dry-run`.
- Один и тот же ASN может встречаться в нескольких сервисах; маршруты дедуплицируются.
- При `--withdraw` скрипт удаляет из FRR анонсы, которых больше нет в RADB.
- Скрипт работает только с IPv4-маршрутами.

## Типовые проблемы

- `Required command 'whois' is not available in PATH` — установите WHOIS-клиент.
- `Required command 'vtysh' is not available in PATH` — установите FRRouting.
- `permission denied` при `vtysh` — дайте пользователю доступ к FRR.
- таймауты WHOIS — уменьшите `whois_concurrency`, увеличьте `fetch_retries` или `whois_timeout_sec`.
- пустой результат — проверьте, что у указанных ASN есть `route:` записи в RADB.
