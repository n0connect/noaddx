# Publishes noaddx. as a Tor onion service (make onion). tor runs unprivileged and connects only
# to nginx's onion listener; the service identity key lives in the tor_data volume.
FROM debian:trixie-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends tor \
  && rm -rf /var/lib/apt/lists/*

COPY tor/torrc /etc/tor/torrc

USER debian-tor
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
