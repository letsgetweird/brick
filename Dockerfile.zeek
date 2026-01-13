FROM zeek/zeek:lts

USER root
RUN apt-get update && apt-get install -y git cmake make gcc g++ libssl-dev libpcap-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

ARG GITHUB_USER=letsgetweird

# Create zkg config directory and configure it
RUN mkdir -p /root/.zkg && \
    echo '[paths]' > /root/.zkg/config && \
    echo 'state_dir = /root/.zkg/state' >> /root/.zkg/config && \
    echo 'script_dir = /usr/local/zeek/share/zeek/site' >> /root/.zkg/config && \
    echo 'plugin_dir = /usr/local/zeek/lib/zeek/plugins' >> /root/.zkg/config && \
    echo 'zeek_dist = /usr/local/zeek' >> /root/.zkg/config && \
    echo 'bin_dir = /usr/local/zeek/bin' >> /root/.zkg/config && \
    echo '[sources]' >> /root/.zkg/config && \
    echo 'zeek = https://github.com/zeek/packages' >> /root/.zkg/config

# Install ICS plugins
RUN /usr/local/zeek/bin/zkg install --skiptests --force https://github.com/${GITHUB_USER}/icsnpp-modbus || echo "Modbus install failed"

RUN /usr/local/zeek/bin/zkg install --skiptests --force https://github.com/${GITHUB_USER}/icsnpp-enip || echo "EtherNet/IP install failed"

RUN /usr/local/zeek/bin/zkg install --skiptests --force https://github.com/${GITHUB_USER}/icsnpp-s7comm || echo "S7comm install failed"

# Verify what got installed
RUN /usr/local/zeek/bin/zkg list

WORKDIR /data/zeek_logs
