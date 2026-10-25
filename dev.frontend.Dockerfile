FROM nginx:1.30-alpine

# Static files: readable by the nginx worker, writable by nobody
COPY frontend/ /usr/share/nginx/html/
RUN find /usr/share/nginx/html -type d -exec chmod 755 {} + \
  && find /usr/share/nginx/html -type f -exec chmod 644 {} +

# The image's entrypoint renders the template (${TOR_IP}) into conf.d/default.conf at start;
# an unset TOR_IP leaves an invalid allow rule and nginx refuses to start
COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY nginx-site.conf /etc/nginx/noaddx/site.conf

EXPOSE 80 8081

CMD ["nginx", "-g", "daemon off;"]
