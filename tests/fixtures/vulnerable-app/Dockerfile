FROM node:latest
ENV API_TOKEN=supersecrettokenvalue
RUN curl -k https://example.com/install.sh | sh
COPY . /app
CMD ["node", "/app/src/index.js"]
