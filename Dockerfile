# 离线指令授权快照复核服务：纯 Node.js，零运行时依赖。
FROM node:20-alpine

WORKDIR /app

# 零外部依赖：直接拷贝源码与测试即可运行。
COPY package.json ./
COPY src ./src
COPY test ./test

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080

# 默认启动静态复核页面与 API；verify 服务会覆盖 command 运行验收测试。
CMD ["node", "src/server.js"]
