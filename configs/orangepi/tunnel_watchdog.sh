#!/bin/sh
# ==============================================================================
# tunnel_watchdog.sh — Сторожевой таймер туннеля и локального DNS
# Хост: Orange Pi 4 LTS (Armbian)
# ==============================================================================
# Назначение:
# 1. Проверка доступности удаленного туннельного IP (10.0.20.1 в ЦОД).
# 2. Проверка локального DNS-сервера (AdGuard Home на 127.0.0.1:53).
# 3. При сбое: сброс плавающего IP (192.168.1.9) с сетевого интерфейса eth0.
#    Это дает сигнал роутеру перехватить адрес и переключить режим.
# 4. При восстановлении: проверка доступности IP через arping и возврат адреса.
# ==============================================================================

HQ_TUNNEL_IP="10.0.20.1"        # IP сервера ЦОД внутри туннеля wg0
FLOAT_IP="192.168.1.9"          # Плавающий виртуальный IP шлюза/DNS
FLOAT_IFACE="eth0"              # Сетевой интерфейс LAN
FAIL_FILE="/run/tunnel_fail_count"
FAIL_THRESHOLD=2                # Порог сбоев для инициации отключения

SERVICES_HEALTHY=1

# 1. Проверяем пинг до удаленного конца туннеля в ЦОД
ping -c 2 -W 2 "$HQ_TUNNEL_IP" > /dev/null 2>&1 || SERVICES_HEALTHY=0

# 2. Проверяем локальный DNS-сервер (порт 53)
nc -z -w 2 127.0.0.1 53 || SERVICES_HEALTHY=0

# Проверяем, назначен ли сейчас виртуальный IP на нашем интерфейсе
HAS_IP=0
ip -4 addr show dev "$FLOAT_IFACE" | grep -q "$FLOAT_IP/" && HAS_IP=1

if [ "$SERVICES_HEALTHY" -eq 0 ]; then
    # --- СЕРВИСЫ НЕ В ПОРЯДКЕ ---
    N=$(cat "$FAIL_FILE" 2>/dev/null || echo 0)
    N=$((N+1))
    echo "$N" > "$FAIL_FILE"

    if [ "$N" -ge "$FAIL_THRESHOLD" ] && [ "$HAS_IP" -eq 1 ]; then
        # Снимаем плавающий IP, чтобы роутер мог его перехватить
        ip addr del "$FLOAT_IP/24" dev "$FLOAT_IFACE" 2>/dev/null
        logger -t tunnel_watchdog "UNHEALTHY после $N проверок. $FLOAT_IP снят с $FLOAT_IFACE."
    fi
else
    # --- СЕРВИСЫ В ПОРЯДКЕ ---
    if [ -f "$FAIL_FILE" ] && [ "$(cat "$FAIL_FILE")" != "0" ]; then
        logger -t tunnel_watchdog "Services HEALTHY. Туннель и DNS доступны."
    fi
    echo 0 > "$FAIL_FILE"

    # Если сервисы здоровы, но виртуального адреса у нас еще нет
    if [ "$HAS_IP" -eq 0 ]; then
        FREE=1
        # Проверяем, освободил ли роутер этот IP (Duplicate Address Detection)
        if command -v arping >/dev/null 2>&1; then
            arping -c 2 -w 2 -D -I "$FLOAT_IFACE" "$FLOAT_IP" >/dev/null 2>&1 || FREE=0
        fi

        if [ "$FREE" -eq 1 ]; then
            ip addr add "$FLOAT_IP/24" dev "$FLOAT_IFACE" 2>/dev/null
            arping -U -c 3 -I "$FLOAT_IFACE" "$FLOAT_IP" >/dev/null 2>&1
            logger -t tunnel_watchdog "$FLOAT_IP возвращен на $FLOAT_IFACE."
        else
            logger -t tunnel_watchdog "$FLOAT_IP еще занят (роутером), жду следующий цикл."
        fi
    fi
fi
