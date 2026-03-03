#!/usr/bin/env bash
# BIRD2 HA entrypoint for VPN/DNS Blocker
# Starts BIRD2, then polls the vpn-dns-blocker health endpoint and
# enables/disables the VIP BGP announcement accordingly.
#
# Environment variables (set in docker-compose.yml or .env):
#   NODE_IP          This node's real IP (used as BIRD router-id)
#   VIP              Virtual IP to announce (default: 192.168.1.254)
#   BGP_UPSTREAM_IP  Upstream router IP
#   BGP_UPSTREAM_AS  Upstream router AS number
#   BGP_LOCAL_AS     This node's AS number (default: 65001)
#   HEALTH_URL       vpn-dns-blocker health endpoint (default: http://localhost:8080/api/stats)
#   HEALTH_INTERVAL  Poll interval in seconds (default: 3)
#   FAILOVER_THRESH  Consecutive failures before withdrawing VIP (default: 2)

set -euo pipefail

VIP="${VIP:-192.168.1.254}"
HEALTH_URL="${HEALTH_URL:-http://localhost:8080/api/stats}"
HEALTH_INTERVAL="${HEALTH_INTERVAL:-3}"
FAILOVER_THRESH="${FAILOVER_THRESH:-2}"
BIRD_CONF=/etc/bird/bird.conf
BIRD_SOCK=/run/bird/bird.ctl

# ── Validate required variables ─────────────────────────────────────────────
for var in NODE_IP BGP_UPSTREAM_IP BGP_UPSTREAM_AS; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: required environment variable $var is not set" >&2
    exit 1
  fi
done

BGP_LOCAL_AS="${BGP_LOCAL_AS:-65001}"

# ── Substitute placeholders in bird.conf ────────────────────────────────────
sed -i \
  -e "s|\${NODE_IP}|${NODE_IP}|g" \
  -e "s|\${VIP}|${VIP}|g" \
  -e "s|\${BGP_UPSTREAM_IP}|${BGP_UPSTREAM_IP}|g" \
  -e "s|\${BGP_UPSTREAM_AS}|${BGP_UPSTREAM_AS}|g" \
  -e "s|\${BGP_LOCAL_AS}|${BGP_LOCAL_AS}|g" \
  "$BIRD_CONF"

echo "[HA] BIRD2 config:"
echo "  node=${NODE_IP}  vip=${VIP}/32  upstream=${BGP_UPSTREAM_IP} AS${BGP_UPSTREAM_AS}  local AS${BGP_LOCAL_AS}"

# ── Start BIRD2 ─────────────────────────────────────────────────────────────
mkdir -p /run/bird
bird -c "$BIRD_CONF" -s "$BIRD_SOCK"
echo "[HA] BIRD2 started"

# ── VIP helper functions ─────────────────────────────────────────────────────
vip_enable() {
  ip addr add "${VIP}/32" dev lo 2>/dev/null || true
  birdc -s "$BIRD_SOCK" "enable VIP" >/dev/null 2>&1 || true
  echo "[HA] VIP ${VIP} enabled — BGP route announced"
}

vip_disable() {
  birdc -s "$BIRD_SOCK" "disable VIP" >/dev/null 2>&1 || true
  ip addr del "${VIP}/32" dev lo 2>/dev/null || true
  echo "[HA] VIP ${VIP} withdrawn — BGP route retracted"
}

# Withdraw on container exit
trap 'echo "[HA] shutting down — withdrawing VIP"; vip_disable; bird -s "$BIRD_SOCK" down 2>/dev/null || true' EXIT INT TERM

# ── Health-check loop ────────────────────────────────────────────────────────
state="unknown"   # current VIP state: "up" | "down" | "unknown"
fails=0

echo "[HA] starting health-check loop (interval=${HEALTH_INTERVAL}s, thresh=${FAILOVER_THRESH})"

while true; do
  if curl -fs --max-time 2 "$HEALTH_URL" > /dev/null 2>&1; then
    fails=0
    if [ "$state" != "up" ]; then
      vip_enable
      state="up"
    fi
  else
    fails=$(( fails + 1 ))
    echo "[HA] health check failed (${fails}/${FAILOVER_THRESH})"

    if [ "$fails" -ge "$FAILOVER_THRESH" ] && [ "$state" != "down" ]; then
      vip_disable
      state="down"
    fi
  fi

  sleep "$HEALTH_INTERVAL"
done
