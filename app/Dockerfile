FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm config set registry https://registry.npmjs.org/ && \
    npm ci --only=production
COPY src/server.js ./

RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001
USER nodejs

EXPOSE 3000
CMD ["node", "server.js"]