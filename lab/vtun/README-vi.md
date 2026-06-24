# Lab V.11 — vtun full-tunnel live (vtund 3.0.4 THẬT)

Kiểm chứng **driver `Drivers.Vtun`** end-to-end với **vtund 3.0.4** (apt `vtun`) THẬT: client .NET bắt tay
challenge-response (MD5 + Blowfish-ECB) → data plane length-prefix → **ICMP 2 chiều** qua tunnel.

## Thành phần
- [`Dockerfile`](Dockerfile) — image `lab-vtun` = Ubuntu 24.04 + `apt install vtun` (vtund 3.0.4-2ubuntu3) + tcpdump/iproute2.
- [`vtund.conf`](vtund.conf) — server 1 host `test`: `passwd pass`, `type tun`, `proto tcp`, `encrypt no`, `compress no`,
  tunnel server `10.11.0.1` ↔ client `10.11.0.2` (point-to-point), `up`/`down` chạy `ip addr ... peer`.
- [`setup-server.sh`](setup-server.sh) — entrypoint: tạo `/dev/net/tun`, bật ip_forward, chạy `vtund -s -n -f ... -P 5000`
  (server foreground).
- [`docker-compose.yml`](docker-compose.yml) — 2 container trên bridge `labnet`: `vtun-server` (image lab-vtun) +
  `client` (runtime-deps, sleep infinity để `docker exec` harness).
- `harness/` — runner .NET (KHÔNG trong solution): publish self-contained linux-x64, chạy `VtunConnection` thật +
  `TcpIpStack`, ping server qua tunnel. Args: `<serverHost> <port> <hostName> <password> <tunnelAddr/cidr> <peerAddr>`.

## Chạy (trên VM `ssh vpnlab`, thư mục `~/vtun-lab/`)
```sh
# 1) publish harness (trên máy dev) → scp vào ~/vtun-lab/client-bin/
dotnet publish lab/vtun/harness -c Release -r linux-x64 -o publish
scp -r lab/vtun/{Dockerfile,vtund.conf,setup-server.sh,docker-compose.yml} vpnlab:~/vtun-lab/
scp -r lab/vtun/harness/publish/* vpnlab:~/vtun-lab/client-bin/

# 2) build image + lên lab
docker build -t lab-vtun:latest .
docker compose up -d

# 3) chạy client harness
docker exec vtun-client sh -c 'cp -r /app /tmp/app && chmod +x /tmp/app/harness && \
  /tmp/app/harness vtun-server 5000 test pass 10.11.0.2/24 10.11.0.1'

# 4) dọn
docker compose down -v
```

## Kết quả VALIDATE LIVE ✓ (2026-06-24)
Client log:
```
[vtun] handshake: authenticated; server flags = Tcp, KeepAlive, Tun
[+] tunnel up. server flags = Tcp, KeepAlive, Tun, tunnel IP = 10.11.0.2/24, peer = 10.11.0.1, mtu = 1450
[ping 1] reply from 10.11.0.1: 38.7 ms ; [ping 2..4] ~0.4 ms
[✓✓] FULL-TUNNEL LIVE OK — 4/4 ICMP echo replies through vtund (2-way ICMP confirmed)
```
Server log (vtund `-n` debug):
```
authentication[18]: Use SSL-aware challenge/response        # đúng nhánh Blowfish/MD5 (HAVE_SSL)
authentication[18]: Session test[172.19.0.3:53868] opened   # auth OK, session mở
test tun tun0[18]                                            # tun device tạo + bind (data plane lên)
test closing[18]: Session test closed                       # CONN_CLOSE teardown nhận đúng
```
**Reject path live ✓**: sai password → server `Denied connection from ...` → client `VpnAuthenticationException (got 'ERR')`.

**Wire (tcpdump eth0 tcp/5000)**: histogram độ dài segment = `50` (×6, khối auth 50-byte NUL-pad: greeting/HOST/CHAL/
response/FLAGS), `62` (data frame = 2-byte length header + 60-byte ICMP/IP), `2` (×4, control frame ECHO_REQ/ECHO_REP
0-payload). Khớp byte-for-byte spec vtun 3.0.x.

**0 BUG** — golden vector OpenSSL (`MD5("pass")` → `BF-ECB` → `7416f64c…`) khóa offline trước nên challenge-response
đúng ngay lần đầu live.

## Ghi chú bảo mật
⚠️ vtun auth/data crypto **legacy yếu** (Blowfish-ECB/MD5-challenge; `encrypt no` ⇒ data plane cleartext). Lab interop
only — KHÔNG dùng vtun cho production.
