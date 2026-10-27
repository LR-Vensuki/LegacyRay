VPN-клиент для всего устройства на **iOS 4.0 – 7.x**: VLESS, VMess, Trojan, Shadowsocks, SOCKS, AmneziaWG и WireGuard. На iOS 4–6 интерфейс нарисован так, как Apple рисовала iOS 6; на iOS 7 он родной плоский. На iPad — раскладка split view.

LegacyRay — форк [senko](https://github.com/sqmrak/senko) от sqmrak (GPL-2.0): сетевое ядро и демон взяты из senko и доработаны, интерфейс написан заново.

**Протоколы**: VLESS (TCP, TLS, Reality + xtls-rprx-vision, WebSocket, XHTTP, gRPC), Trojan, Shadowsocks, SOCKS5 и HTTP(S), AmneziaWG 1.0/1.5/2.0, WireGuard.

**Подписки**: URI-списки, base64, happ-ссылки (включая crypt5), Xray и sing-box JSON, Clash YAML, Shadowrocket и Surge INI. Трафик, срок и напоминания об окончании подписки.

**Возможности**

- Маршрутизация с правилами `geosite:` и `geoip:`, профили Happ, раздельное туннелирование по сайтам.
- Фрагментация TLS-рукопожатия, kill switch, свой DNS, раздача SOCKS5-прокси в локальной сети.
- Свой сервер: по SSH ставит Xray Reality и/или AmneziaWG на ваш VPS и управляет его клиентами.
- Импорт из буфера, QR-кода (камера и «Фото»), файла, ключей `vpn://` и `.conf`.
- Бережёт батарею: демон просыпается только тогда, когда есть работа.
- Русский, английский и китайский языки.

**Как трафик попадает в туннель**: через pf (iOS 7), ipfw или хук `connect()` из MobileSubstrate — что найдётся в системе. `pfctl` и `ipfw` в пакет не входят, их ставят из репозиториев Cydia.

При первой установке SpringBoard перезапустится сам, когда будет готова иконка: на старом телефоне это занимает десятки секунд.

*Скриншоты — рендеры макета интерфейса, а не снимки с устройства: на iPhone детали могут отличаться.*
