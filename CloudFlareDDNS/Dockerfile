ARG BUILD_FROM
FROM $BUILD_FROM
ARG S6_ARCH

ENV LANG C.UTF-8 S6_BEHAVIOUR_IF_STAGE2_FAILS=2 CF_API=https://api.cloudflare.com/client/v4 RRTYPE=A

COPY root /

RUN apk update && apk upgrade && apk add --no-cache jq\
	&& chmod +x /root/app/cloudflare.sh

CMD ["/root/app/cloudflare.sh"]
