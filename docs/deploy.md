# Отдельная установка на vds-kg

Новый пакет тестируется в `/opt/bgpfeed-test`. Боевой каталог
`/opt/get_youtube_frr`, его конфиг и способ запуска не изменяются.

## Production

С 30.07.2026 production работает из `/opt/bgpfeed`:

- `/opt/bgpfeed/config.yaml` — проверенный v2-конфиг;
- `bgpfeed.service` — `run --withdraw`, полная синхронизация FRR;
- `bgpfeed.timer` — запуск каждые 6 часов;
- `get-youtube-frr.timer` — disabled, но каталог и unit легаси сохранены.

Проверка после переключения: 3215 configured IPv4 network, IPv6 — 0, обе
BGP-сессии Established, повторный reconciliation — add=0/remove=0.

Production rollback одной командой:

```bash
systemctl disable --now bgpfeed.timer && systemctl enable --now get-youtube-frr.timer && systemctl start get-youtube-frr.service
```

Последняя часть немедленно возвращает во FRR набор легаси; ждать следующего
срабатывания таймера не требуется.

На vds-se2 (`91.223.169.128`, AS65001) production также работает из
`/opt/bgpfeed`. Проверенный результат: 4506 IPv4 network, IPv6 — 0, обе
BGP-сессии Established, повторный reconciliation add=0/remove=0. Legacy-unit
на этом узле исторически запускался без `--withdraw`, поэтому точный rollback
должен явно передать этот флаг:

```bash
systemctl disable --now bgpfeed.timer && systemctl enable --now get-youtube-frr.timer && /usr/bin/python3 /opt/get_youtube_frr/getroutes.py -c /opt/get_youtube_frr/config.yaml --withdraw
```

На vds-se2 дополнительно включены `geosite:anthropic`, `geosite:openai`,
`geosite:instagram` + `geoip:facebook` и `geosite/geoip:telegram`. Ранее
обнаруженные адреса повторно сопоставляются через Cymru до истечения TTL,
чтобы смена DNS-ответа не создавала дыру в covering-наборе.

Выделенные ручные ASN разворачиваются полностью. Доменные части Anthropic,
OpenAI, Instagram и Telegram используют `strategy: covering_prefix`, потому
что их DNS приводит в общие AWS/Akamai/Microsoft/Cloudflare ASN. Все живые
адреса из state сохраняют covering до TTL; geoip-категории анонсируются
полностью. Итоговый общий набор точно схлопывается непосредственно перед FRR.

## Обновление стенда

С локальной машины:

```bash
COPYFILE_DISABLE=1 tar czf - bgpfeed contrib | ssh root@81.85.75.47 'tar xzf - -C /opt/bgpfeed-test'
```

Первичная установка Python-окружения:

```bash
python3 -m venv /opt/bgpfeed-test/venv
/opt/bgpfeed-test/venv/bin/pip install pyyaml loguru dnspython
```

Конфиги стенда лежат рядом с кодом. В них должны использоваться отдельные
`state_file`, `log_file` и `feeds.cache_dir` внутри `/opt/bgpfeed-test`.

## Проверка до FRR

```bash
PYTHONPATH=/opt/bgpfeed-test /opt/bgpfeed-test/venv/bin/python -m bgpfeed feeds update --config /opt/bgpfeed-test/config-v2.yaml
PYTHONPATH=/opt/bgpfeed-test /opt/bgpfeed-test/venv/bin/python -m bgpfeed discover --config /opt/bgpfeed-test/config-v2.yaml
PYTHONPATH=/opt/bgpfeed-test /opt/bgpfeed-test/venv/bin/python -m bgpfeed show prefixes --config /opt/bgpfeed-test/config-v2.yaml
PYTHONPATH=/opt/bgpfeed-test /opt/bgpfeed-test/venv/bin/python -m bgpfeed run --withdraw --dry-run --config /opt/bgpfeed-test/config-v2-final.yaml
```

До включения `run` нужно сохранить текущий список анонсов легаси и сравнить
покрытие, а не только количество строк. Известная ожидаемая разница на старом
v1-конфиге: 8119 маршрутов легаси против 1355 после точного схлопывания при
том же покрытии. Любое другое расхождение разбирается до переключения.

## systemd

Сначала устанавливается только безопасный почасовой `discover`:

```bash
install -m 0644 /opt/bgpfeed-test/contrib/bgpfeed-test-discover.service /etc/systemd/system/
install -m 0644 /opt/bgpfeed-test/contrib/bgpfeed-test-discover.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now bgpfeed-test-discover.timer
```

`bgpfeed-test-run.service` вызывает `run --withdraw`: добавляет новый импорт,
затем удаляет все stale `network` из `router bgp 65004`. Его таймер нельзя
включать одновременно с легаси-запуском. После сверки и явного решения о
переключении:

```bash
install -m 0644 /opt/bgpfeed-test/contrib/bgpfeed-test-run.service /etc/systemd/system/
install -m 0644 /opt/bgpfeed-test/contrib/bgpfeed-test-run.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now bgpfeed-test-run.timer
```

Проверенный на vds-kg `config-v2-final.yaml` объединяет `geosite:youtube`,
`geoip:google` и семь ручных ASN, которые закрывают недоступные с этой точки
GGC-диапазоны. Финальный живой план содержал 3215 IPv4-префиксов; IPv6 на
границе FRR отфильтрован согласно scope v1.

## Откат

До переключения откат не требуется: легаси продолжает работать, тестовый
`discover` FRR не меняет.

После переключения новый ежедневный запуск отключается одной командой:

```bash
systemctl disable --now bgpfeed-test-run.timer
```

Затем включается прежний легаси-unit или cron-задание тем же способом, которым
оно управлялось до миграции. Каталог `/opt/get_youtube_frr` и его файлы всё
это время остаются на месте, поэтому восстановления кода или конфига нет.
