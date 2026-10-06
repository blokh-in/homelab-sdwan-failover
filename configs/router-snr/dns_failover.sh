#!/bin/sh
# ==============================================================================
# dns_failover.sh — Скрипт динамического переключения DNS и PBR-маршрутизации
# Оборудование: SNR-CPE-AX1 (OpenWrt)
# ==============================================================================
# Назначение:
# 1. Отслеживание доступности Orange Pi (основного шлюза и DNS AdGuard Home).
# 2. Перехват плавающего IP (192.168.1.9) роутером при аварии одноплатника.
# 3. Перенаправление DNS-запросов в резервный туннель ЦОД (wg-snr) через DNAT.
# 4. Сброс Policy-Based Routing (PBR) для прямого выхода клиентов через WAN провайдера.
# 5. Детекция восстановления Orange Pi через независимый сервисный IP (192.168.1.19).
# ==============================================================================

# --- Сетевые параметры ---
ORANGE_PI="192.168.1.9"          # Плавающий виртуальный IP (VIP шлюза и DNS)
ORANGE_PI_PING="192.168.1.19"    # Сервисный постоянный IP Orange Pi для проверок
HQ_SERVER="10.0.10.1"            # IP DNS-сервера ЦОД внутри резервного туннеля wg-snr
SERVER_KZ="192.168.1.10"         # Домашний сервер (всегда идет напрямую в интернет)
HQ_WG_ENDPOINT="203.0.113.186"   # Публичный IP сервера ЦОД (защита от петли)
BR_IFACE="br-lan"                # LAN-интерфейс роутера

# ==============================================================================
# Проверка текущего состояния: перехвачен ли IP .9 роутером?
# ==============================================================================
if ip addr show dev "$BR_IFACE" | grep -q "$ORANGE_PI/32"; then
    # --------------------------------------------------------------------------
    # РЕЖИМ ВОССТАНОВЛЕНИЯ (RECOVERY MODE)
    # Роутер держит адрес .9. Проверяем, ожил ли Orange Pi.
    # Проверка выполняется DNS-запросом к уникальному имени на сервисный IP (.19),
    # чтобы обойти локальный кэш и убедиться в реальной работе резолвера.
    # --------------------------------------------------------------------------
    if timeout 2 nslookup "check-$(date +%s).google.com" "$ORANGE_PI_PING" > /dev/null 2>&1; then
        # 1. Снимаем виртуальный IP с интерфейса роутера
        ip addr del "$ORANGE_PI/32" dev "$BR_IFACE" 2>/dev/null

        # 2. Удаляем временные правила перенаправления DNS в ЦОД
        iptables -t nat -D PREROUTING -d "$ORANGE_PI" -p udp --dport 53 -j DNAT --to-destination "$HQ_SERVER:53" 2>/dev/null
        iptables -t nat -D PREROUTING -d "$ORANGE_PI" -p tcp --dport 53 -j DNAT --to-destination "$HQ_SERVER:53" 2>/dev/null
        iptables -t nat -D POSTROUTING -o wg-snr -j MASQUERADE 2>/dev/null

        # 3. Восстанавливаем PBR-маршрутизацию по умолчанию через Orange Pi (таблица 100)
        ip route replace default via "$ORANGE_PI" dev "$BR_IFACE" table 100

        # 4. Восстанавливаем правила ip rule (с проверкой на идемпотентность)
        # Локальный трафик между клиентами LAN — через основную таблицу
        ip rule show | grep -q "^80:.*to 192.168.1.0/24 lookup main$" || \
            ip rule add to 192.168.1.0/24 lookup main priority 80

        # Трафик от самой Orange Pi — не заворачивать обратно на нее
        ip rule show | grep -q "^90:.*from $ORANGE_PI lookup main$" || \
            ip rule add from "$ORANGE_PI" lookup main priority 90

        # АНТИ-ПЕТЛЯ: Прямой трафик до публичного IP ЦОД идет мимо туннеля
        ip rule show | grep -q "^92:.*to $HQ_WG_ENDPOINT lookup main$" || \
            ip rule add to "$HQ_WG_ENDPOINT" lookup main priority 92

        # Трафик со служебного IP Orange Pi идет напрямую
        ip rule show | grep -q "^93:.*from $ORANGE_PI_PING lookup main$" || \
            ip rule add from "$ORANGE_PI_PING" lookup main priority 93

        # ИЗОЛЯЦИЯ: Домашний сервер server-kz идет напрямую через провайдера
        ip rule show | grep -q "^95:.*from $SERVER_KZ lookup main$" || \
            ip rule add from "$SERVER_KZ" lookup main priority 95

        # Весь остальной трафик LAN заворачиваем в таблицу 100 (шлюз Orange Pi)
        ip rule show | grep -q "^100:.*from 192.168.1.0/24 lookup 100$" || \
            ip rule add from 192.168.1.0/24 lookup 100 priority 100

        logger -t dns_failover "Orange Pi UP (проверен через $ORANGE_PI_PING). DNS и маршрутизация восстановлены."
    fi

else
    # --------------------------------------------------------------------------
    # ШТАТНЫЙ РЕЖИМ (NORMAL MODE)
    # Проверяем доступность Orange Pi по ICMP
    # --------------------------------------------------------------------------
    if ping -I "$BR_IFACE" -c 2 -W 1 "$ORANGE_PI" > /dev/null 2>&1; then
        # Orange Pi доступна — гарантируем актуальность PBR-правил
        ip route replace default via "$ORANGE_PI" dev "$BR_IFACE" table 100

        ip rule show | grep -q "^80:.*to 192.168.1.0/24 lookup main$" || \
            ip rule add to 192.168.1.0/24 lookup main priority 80

        ip rule show | grep -q "^90:.*from $ORANGE_PI lookup main$" || \
            ip rule add from "$ORANGE_PI" lookup main priority 90

        ip rule show | grep -q "^92:.*to $HQ_WG_ENDPOINT lookup main$" || \
            ip rule add to "$HQ_WG_ENDPOINT" lookup main priority 92

        ip rule show | grep -q "^93:.*from $ORANGE_PI_PING lookup main$" || \
            ip rule add from "$ORANGE_PI_PING" lookup main priority 93

        ip rule show | grep -q "^95:.*from $SERVER_KZ lookup main$" || \
            ip rule add from "$SERVER_KZ" lookup main priority 95

        ip rule show | grep -q "^100:.*from 192.168.1.0/24 lookup 100$" || \
            ip rule add from 192.168.1.0/24 lookup 100 priority 100

    else
        # ----------------------------------------------------------------------
        # АВАРИЯ: Orange Pi не отвечает!
        # Перехватываем виртуальный IP на себя и переключаем DNS в ЦОД
        # ----------------------------------------------------------------------
        # 1. Присваиваем IP себе
        ip addr add "$ORANGE_PI/32" dev "$BR_IFACE"

        # 2. Оповещаем сеть через Gratuitous ARP (сброс ARP-таблиц клиентов)
        if command -v arping >/dev/null 2>&1; then
            arping -U -c 3 -I "$BR_IFACE" "$ORANGE_PI" 2>/dev/null
        fi

        # 3. Перенаправляем DNS-запросы на резервный сервер в ЦОД через wg-snr
        iptables -t nat -D PREROUTING -d "$ORANGE_PI" -p udp --dport 53 -j DNAT --to-destination "$HQ_SERVER:53" 2>/dev/null
        iptables -t nat -D PREROUTING -d "$ORANGE_PI" -p tcp --dport 53 -j DNAT --to-destination "$HQ_SERVER:53" 2>/dev/null
        iptables -t nat -A PREROUTING -d "$ORANGE_PI" -p udp --dport 53 -j DNAT --to-destination "$HQ_SERVER:53"
        iptables -t nat -A PREROUTING -d "$ORANGE_PI" -p tcp --dport 53 -j DNAT --to-destination "$HQ_SERVER:53"
        iptables -t nat -I POSTROUTING -o wg-snr -j MASQUERADE

        # 4. Сбрасываем PBR-правила: трафик идет напрямую в интернет через провайдера
        ip rule del to 192.168.1.0/24 lookup main priority 80 2>/dev/null
        ip rule del from "$ORANGE_PI" lookup main priority 90 2>/dev/null
        ip rule del to "$HQ_WG_ENDPOINT" lookup main priority 92 2>/dev/null
        ip rule del from "$ORANGE_PI_PING" lookup main priority 93 2>/dev/null
        ip rule del from "$SERVER_KZ" lookup main priority 95 2>/dev/null
        ip rule del from 192.168.1.0/24 lookup 100 priority 100 2>/dev/null
        ip route flush table 100 2>/dev/null

        logger -t dns_failover "ВНИМАНИЕ: Orange Pi упала! DNS перенаправлен в ЦОД, интернет пущен напрямую."
    fi
fi
