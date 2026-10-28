FROM nginx:alpine
COPY frontend/index.html /usr/share/nginx/html/index.html
COPY frontend/identity.html /usr/share/nginx/html/identity.html
COPY frontend/api-doc.html /usr/share/nginx/html/api-doc.html
COPY frontend/fonts/ /usr/share/nginx/html/fonts/
COPY frontend/editor.css /usr/share/nginx/html/editor.css
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY docs/agent-api.md /usr/share/nginx/html/docs/agent-api.md
COPY docs/openapi.yaml /usr/share/nginx/html/docs/openapi.yaml
EXPOSE 80
