# Отдельная установка на vds-kg

Новый пакет тестируется в `/opt/bgpfeed-test`. Боевой каталог
`/opt/get_youtube_frr`, его конфиг и способ запуска не изменяются.

## Production

С 30.07.2026 production работает из `/opt/bgpfeed`:

- `/opt/bgpfeed/config.yaml` — проверенный v2-конфиг;
- `bgpfeed.service` — `run --withdraw`, полная синхронизация FRR;
- `bgpfeed.timer` — запуск каждые 6 часов;
- `get-youtube-frr.timer` — disabled, но каталог и unit легаси сохранены.

С 31.07.2026 `geoip:google` работает в режиме `corroborate`, без прямого
анонса всей категории. Проверка: 1042 configured IPv4 network, IPv6 — 0, обе
BGP-сессии Established, повторный reconciliation — add=0/remove=0. Семь
ручных ASN и все восемь известных GGC-префиксов сохранены.

### vds-kg: обновление 08.11.2026

Новая версия установлена в `/opt/bgpfeed`; существующие venv, systemd units
и серверный `config.yaml` сохранены. Текущий конфиг использует восемь ручных
ASN для YouTube, исключения AS396982/AS272082/AS9198 и не содержит
geosite/geoip-категорий (отличается от исторической настройки 31.07 выше).

Перед заменой сохранён полный архив установки, FRR-конфига и units:
`/root/bgpfeed-production-backup-20261107T215516Z/bgpfeed-current.tar.gz`.
SHA256: `0891286e8999dccc6ed0adb9e74bdbae2125133e09aad36bcb97478f6e6cdf79`.
На время замены таймер остановлен, после проверки снова active/enabled.

Проверки на vds-kg: 416 тестов прошли; два запуска штатного
`bgpfeed.service` завершились успешно, оба дали
`current=347 desired=347 add=0 remove=0`. Обе BGP-сессии Established,
каждому соседу отправляется 348 префиксов, оба IPsec CHILD_SA установлены.
FRR running-config и kernel routes не изменились. Добавление/удаление
настоящих маршрутов не потребовалось; искусственный churn не создавался.
Проверка с домашнего LAN-хоста не выполнена.

При обновлении со старого state без поля `managed` сначала проверять
`run --withdraw --dry-run` с отдельной копией state и перенаправленными
путями log/cache: dry-run записывает discovery-state, хотя не меняет FRR.
На vds-kg текущий и desired-наборы совпали, поэтому первый штатный запуск
безопасно записал все 347 префиксов в `managed`; второй подтвердил
идемпотентность. Если наборы различаются, не считать все текущие `network`
управляемыми автоматически: сначала проверить принадлежность stale-маршрутов.

Исторический rollback на legacy (не откат обновления от 08.11):

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

Проверенный на vds-kg конфиг объединяет `geosite:youtube`, семь ручных ASN и
`geoip:google` в режиме `corroborate`. После отключения прямого анонса всей
geoip-категории живой план содержит 1042 IPv4-префикса; IPv6 на границе FRR
отфильтрован согласно scope v1.

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
