# bgpfeed

`bgpfeed` определяет ASN сервиса по доменам с нужной точки наблюдения,
получает префиксы из RADB и анонсирует их во FRRouting. Механизм не содержит
правил для конкретного сервиса: все домены, категории и политики задаются в
YAML.

Новый пакет развёртывается отдельно. Легаси-скрипты `getroutes.py`,
`getroutes_nosum.py` и `youtube_asn_analyzer.py` не изменены, не заменены и
продолжают работать прежним способом.

## Требования

- Python 3.9+
- `whois` для запросов к RADB
- `vtysh` из FRRouting для применения маршрутов
- Python-пакеты `pyyaml`, `loguru`, `dnspython`

```bash
python3 -m pip install pyyaml loguru dnspython
```

## Быстрый старт

Сначала обновить закреплённые фиды и проверить кэш:

```bash
python3 -m bgpfeed feeds update --config config-v2.yaml
python3 -m bgpfeed feeds show --config config-v2.yaml
python3 -m bgpfeed feeds show --category youtube --config config-v2.yaml
```

Выполнить обнаружение без обращения к FRR:

```bash
python3 -m bgpfeed discover --service youtube --config config-v2.yaml
python3 -m bgpfeed show asns --service youtube --config config-v2.yaml
python3 -m bgpfeed show prefixes --service youtube --config config-v2.yaml
```

Проверить полный цикл без изменения FRR, затем применить его:

```bash
python3 -m bgpfeed run --dry-run --config config-v2.yaml
python3 -m bgpfeed run --config config-v2.yaml
```

Синхронизировать FRR: добавить отсутствующие и снять только те `network`,
которые ранее выставил сам `bgpfeed`:

```bash
python3 -m bgpfeed run --withdraw --dry-run --config config-v2.yaml
python3 -m bgpfeed run --withdraw --config config-v2.yaml
```

`discover` и `show` никогда не вызывают `vtysh`. `run --dry-run --withdraw`
читает текущую конфигурацию FRR и печатает точный diff, но не меняет её.
Пустой результат discovery всегда завершает команду ошибкой до обращения к
FRR, поэтому сбой DNS/RADB не может удалить все маршруты. Чужие, ручные и
legacy `network` не снимаются: они перечисляются в предупреждении. При
сокращении учтённого набора больше чем на 50% `run --withdraw` отказывается
менять FRR — порог задаётся через `guards.max_change_ratio`.

## Конфигурация v2

Минимальный сервис может состоять из одной geosite-категории:

```yaml
version: 2

router:
  as_number: 65001
  log_file: logs/bgpfeed.log
  state_file: state/bgpfeed.json

feeds:
  cache_dir: state/feeds
  refresh_days: 7
  offline_ok: true
  geosite:
    url: https://raw.githubusercontent.com/v2fly/domain-list-community/{ref}/data/{category}
    ref: "20260730073441"
  geoip:
    url: https://raw.githubusercontent.com/Loyalsoldier/geoip/{ref}/text/{category}.txt
    ref: d57a38b3e88abe4c93a50a2eb5d55f59fe7607aa

defaults:
  resolve:
    vantage:
      source_ip: 192.0.2.10
      resolvers: [system]

services:
  youtube:
    geosite:
      categories: [youtube]
    geoip:
      categories: [google]
      mode: announce
```

`ref` обязан быть тегом или commit SHA; плавающие ветки `main`/`master`
отклоняются. При `offline_ok: true` недоступный источник заменяется последней
целой копией из кэша. `sha256` задаётся по категориям и проверяется как при
загрузке, так и при чтении кэша:

```yaml
    sha256:
      youtube: "..."
      google: "..."
```

Оборванная загрузка и неверный `sha256` не перезаписывают кэш.

Старый `config.yaml` без `version` по-прежнему поддерживается: перечисленные
`as_numbers` разворачиваются из RADB без доменного discovery.

## Vantage Point И GGC

DNS-запросы привязываются к `resolve.vantage.source_ip`. Это принципиально для
CDN: один домен с домашней машины и с маршрутизирующего VDS может вернуть
разные edge-адреса. Локальный GGC обнаружится только если выбранный резолвер
с этой точки действительно отдаёт адрес провайдерского кэша.

На vds-kg провайдерского рекурсивного DNS нет, поэтому Google Public DNS
возвращает AS15169, а не локальный GGC. Это ограничение сети, не фильтр в
коде. `geoip:google` дополнительно покрывает известные Google/GGC-префиксы,
но не заменяет vantage-резолв.

Живая проверка также показала, что AS36561, подписанная в старом конфиге как
основная YouTube ASN, даёт из RADB только один маршрут. Реальное покрытие на
vds-kg дал AS15169: 104 маршрута после точного схлопывания. Команда
`show asns` выводит эту цену и причину решения для каждой ASN.

## Безопасность И Бюджет

- Суммаризация только точная: `ipaddress.collapse_addresses` не добавляет
  адресное пространство, которого не было в источниках.
- Bogon, private-сети и слишком широкие префиксы отбрасываются guard-ами.
- Выделенные и ручные ASN анонсируются полностью после точного схлопывания.
  Общие cloud/CDN ASN можно явно перевести в `strategy: covering_prefix`,
  сохранив покрытие наблюдаемых и ещё живых state-адресов без всей AWS/Akamai.
- Превышение бюджета журналируется, но не урезает ASN или geoip-категории.
- Перед FRR выполняется финальное точное схлопывание объединённого набора всех
  сервисов.
- Ошибка внешнего источника не превращается в пустой успешный результат.

## Эксплуатация

Примеры systemd находятся в `contrib/`, порядок отдельной установки и отката
описан в `docs/deploy.md`. Юнит обнаружения запускается почасово, полный
`run` раз в сутки. Перед включением таймера обязательно выполнить `run
--dry-run` и сравнить результат с текущими маршрутами.

Production на vds-kg установлен в `/opt/bgpfeed` и запускается
`bgpfeed.timer` каждые 6 часов. Старый `/opt/get_youtube_frr` сохранён для
отката, его timer отключён.

Та же схема включена на vds-se2: локальный AS65001, сервисы старого конфига и
domain/geoip discovery для YouTube, Instagram, Anthropic, OpenAI и Telegram.
Legacy-каталог сохранён, timer отключён.

## Тесты

```bash
python3 -m pytest tests/ -q
```
