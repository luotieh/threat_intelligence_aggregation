#!/usr/bin/env bash
# 纯 docker run 部署脚本(不依赖 docker-compose)
# 等价于 docker-compose.yml 的 5 个服务: postgres / redis / api / worker / beat
# 用法: 在解压后的 release/threat-intel-hub 目录下执行 ./deploy.sh
set -euo pipefail

cd "$(dirname "$0")"

# 可变参数集中放 deploy.conf(与本脚本同目录),改端口/镜像等只改那个文件,
# 不必改脚本、也不必重新打包镜像。参数模板见 deploy.conf.example。
# 优先级: deploy.conf 中写明的项 > 环境变量 > 下方默认值
#         (在 conf 中注释掉的项,则回落到环境变量或默认值)。
[ -f deploy.conf ] && . ./deploy.conf

NET="${NET:-intel-net}"
IMAGE="${IMAGE:-threat-intel-hub:latest}"
PG_IMAGE="${PG_IMAGE:-postgres:16-alpine}"
REDIS_IMAGE="${REDIS_IMAGE:-redis:7-alpine}"
IOC_DIR="${IOC_DIR:-/data/ftp/ioc}"
API_PORT="${API_PORT:-18080}"       # api 对外端口(勿用被占端口,如 xray 的 22128)
PG_PORT="${PG_PORT:-5432}"          # postgres 对外端口
REDIS_PORT="${REDIS_PORT:-6379}"    # redis 对外端口

# 0. 前置检查
if [ ! -f .env ]; then
  echo "[!] 未找到 .env,先执行: cp .env.example .env 并填写 MISP/ta_node 配置"
  exit 1
fi
mkdir -p "$IOC_DIR"

# 1. 自定义网络(容器按名字互相解析,postgres/redis 必须是这两个名字,与 .env 中主机名一致)
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"

# 2. 应用镜像: 已存在则跳过构建(离线部署: 先 docker load 好镜像再跑本脚本)
#    强制重建: FORCE_BUILD=1 ./deploy.sh
if [ "${FORCE_BUILD:-0}" != "1" ] && docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[*] 已存在镜像 $IMAGE,跳过构建(离线模式)。如需重建: FORCE_BUILD=1 ./deploy.sh"
else
  echo "[*] 构建镜像 $IMAGE (需能联网 pip install)..."
  docker build -t "$IMAGE" .
fi

# 3. 依赖组件: postgres / redis
echo "[*] 启动 postgres / redis ..."
docker rm -f postgres redis >/dev/null 2>&1 || true

docker run -d --name postgres --network "$NET" --restart unless-stopped \
  -e POSTGRES_DB=intel -e POSTGRES_USER=intel -e POSTGRES_PASSWORD=intel \
  -v postgres_data:/var/lib/postgresql/data \
  -p "${PG_PORT}:5432" "$PG_IMAGE"

docker run -d --name redis --network "$NET" --restart unless-stopped \
  -p "${REDIS_PORT}:6379" "$REDIS_IMAGE"

# 4. 等 postgres 就绪
echo -n "[*] 等待 postgres 就绪 "
for i in $(seq 1 30); do
  if docker exec postgres pg_isready -U intel -d intel >/dev/null 2>&1; then
    echo " OK"; break
  fi
  echo -n "."; sleep 1
  if [ "$i" -eq 30 ]; then echo " 超时,请检查 docker logs postgres"; exit 1; fi
done

# 5. 应用: api / worker / beat
echo "[*] 启动 api / worker / beat ..."
docker rm -f intel-api intel-worker intel-beat >/dev/null 2>&1 || true

# api: 对外 $API_PORT,挂 release(导出包) 和 ioc 输出目录
docker run -d --name intel-api --network "$NET" --restart unless-stopped \
  --env-file .env -p "${API_PORT}:18080" \
  -v "$PWD/release:/app/release" \
  -v "$IOC_DIR:$IOC_DIR" \
  "$IMAGE"

# worker: Celery 任务实际生成规则文件/导出包,同样需要挂这两个卷
docker run -d --name intel-worker --network "$NET" --restart unless-stopped \
  --env-file .env \
  -v "$PWD/release:/app/release" \
  -v "$IOC_DIR:$IOC_DIR" \
  "$IMAGE" \
  celery -A app.tasks.celery_app.celery_app worker --loglevel=info

# beat: 只做定时调度,不写文件,无需挂卷
docker run -d --name intel-beat --network "$NET" --restart unless-stopped \
  --env-file .env \
  "$IMAGE" \
  celery -A app.tasks.celery_app.celery_app beat --loglevel=info

# 6. 健康检查
echo "[*] 等待 api 启动 ..."
sleep 4
echo "[*] 健康检查 (端口 $API_PORT):"
curl -fsS "http://127.0.0.1:${API_PORT}/health" && echo || echo "[!] health 未通过,查看: docker logs intel-api"

echo
echo "部署完成。常用命令:"
echo "  查看日志:   docker logs -f intel-api"
echo "  查看状态:   docker ps --filter network=$NET"
echo "  停止清理:   docker rm -f intel-api intel-worker intel-beat postgres redis"
echo "  删除网络:   docker network rm $NET"
