# ViSao Mini-Server — Reference

Box: 38.244.152.11 (Type C: nginx splitter + mini-clo :8100 + Next.js landing :3000).

Source live on the box:
- /opt/mini-clo/ — Python FastAPI mini-clo service
- /etc/nginx/sites-enabled/visao — splitter config
- /etc/systemd/system/mini-clo.service — systemd unit
- /opt/mini-landing/ — Next.js white landing

Full setup: docs/03-mini-server-visao.md, docs/07-deployment.md.
