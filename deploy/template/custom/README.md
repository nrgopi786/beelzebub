Client-specific lures. Any `*.yaml` beelzebub service file placed in
`clients/<name>/custom/` is copied verbatim into the rendered config on every
`./deploy.sh up`, replacing a generated file with the same name. Use it for
bespoke login pages, fake app banners, or extra ports for this client.
