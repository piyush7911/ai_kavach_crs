# Emulates the finale target VM: a real vulnerable app (NodeGoat) running from a
# mutable path, reachable over SSH (password) and HTTP, with a restart.sh that
# re-launches the app from /opt/app after we patch it. Build context = repo root.
FROM node:12-alpine

# VM-like access: ssh daemon + password login, plus tools restart.sh needs.
RUN apk add --no-cache openssh bash netcat-openbsd curl tar \
 && ssh-keygen -A \
 && echo "root:kavach" | chpasswd \
 && sed -i 's/#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
 && sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

ENV MONGODB_URI=mongodb://mongo:27017/nodegoat PORT=4000 NODE_ENV=production

# The app lives at a mutable path (so patches + restart.sh take effect), exactly
# like the finale "codebase at a path" on the VM.
WORKDIR /opt/app
COPY benchmark_workspace/nodegoat/ ./
RUN rm -rf node_modules && npm install --production --no-cache

# Also ship the source as a tar.gz, to rehearse the "pull the codebase" step.
RUN tar czf /root/app.tar.gz --exclude=node_modules -C /opt app

COPY finale_emulator/restart.sh /opt/restart.sh
COPY finale_emulator/entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/restart.sh /opt/entrypoint.sh

EXPOSE 22 4000
ENTRYPOINT ["/opt/entrypoint.sh"]
