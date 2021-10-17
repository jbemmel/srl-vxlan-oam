ARG SR_LINUX_RELEASE
FROM srl/custombase:$SR_LINUX_RELEASE AS final

# Install scapy, netns and graphscii
RUN sudo pip3 install scapy netns graphscii

# Integrate vxlan traceroute CLI command
COPY src/srl-vxlan-oam/cli/* /opt/srlinux/python/virtual-env/lib/python3.6/site-packages/srlinux/mgmt/cli/plugins/
RUN sudo sh -c ' echo "vxlan_traceroute = srlinux.mgmt.cli.plugins.vxlan_traceroute:Plugin" \
  >> /opt/srlinux/python/virtual-env/lib/python3.6/site-packages/srlinux-0.1-py3.6.egg-info/entry_points.txt'

RUN sudo mkdir --mode=0755 -p /etc/opt/srlinux/appmgr/
# COPY --chown=srlinux:srlinux ./srl-whatever-agent.yml /etc/opt/srlinux/appmgr
COPY ./src /opt/demo-agents/

# Add in auto-config agent sources too
# COPY --from=srl/auto-config-v2:latest /opt/demo-agents/ /opt/demo-agents/

# run pylint to catch any obvious errors
RUN PYTHONPATH=$AGENT_PYTHONPATH pylint --load-plugins=pylint_protobuf -E /opt/demo-agents/srl-vxlan-oam

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_VXLAN_OAM_RELEASE="[custom build]"
ENV SRL_VXLAN_OAM_RELEASE=$SRL_VXLAN_OAM_RELEASE
