FROM node:24-alpine AS build
# hacer la carpeta 'app' el directorio de trabajo actual
WORKDIR /app

COPY package*.json ./
RUN npm ci

# copiar los archivos y carpetas del proyecto al directorio de trabajo actual (es decir, la carpeta 'app')
COPY . .
RUN npm run build


FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN rm -rf /usr/share/nginx/html/*
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80