FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install --production
COPY server.js .
RUN mkdir -p /data/projects
VOLUME ["/data"]
EXPOSE 3001
CMD ["node", "server.js"]
