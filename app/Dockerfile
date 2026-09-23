# app/Dockerfile
#
# Minimal reference container used to exercise Trivy image scanning in CI.
# Pinned base image, non-root runtime user, production-only dependencies.
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

USER node

EXPOSE 3000

CMD ["node", "server.js"]
