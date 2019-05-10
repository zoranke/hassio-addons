ARG BUILD_FROM
FROM $BUILD_FROM

ENV LANG C.UTF-8

COPY root /

RUN apk update && apk upgrade && apk add --no-cache jq\
	&& chmod +x /root/app/cloudflare.sh

CMD ["/root/app/cloudflare.sh"]
