FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --only=prod=false
COPY tsconfig.json ./
COPY src ./src
RUN npx tsc -p .
EXPOSE 3001
CMD ["node", "dist/index.js"]
