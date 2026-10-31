# syntax=docker/dockerfile:1.7
FROM python:3.14-slim AS backend
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt
COPY backend/app ./backend/app
COPY backend/scripts ./backend/scripts
COPY models ./models
COPY data ./data
WORKDIR /app/backend
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]

FROM node:24-alpine AS frontend-build
WORKDIR /web
COPY frontend/package.json frontend/tsconfig.json frontend/tsconfig.app.json frontend/vite.config.ts frontend/index.html ./
COPY frontend/src ./src
RUN npm install && npm run build

FROM nginx:1.29-alpine AS frontend
COPY --from=frontend-build /web/dist /usr/share/nginx/html
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx","-g","daemon off;"]
