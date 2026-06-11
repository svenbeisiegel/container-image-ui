# container-ui

A zero-dependency, Node.js web UI for managing container images through the
`docker` or `crictl` CLI.

## Features

- Lists all images (name, tag, size) in a Jira-styled table.
- Per-image actions: **Details** (shows image ID), **Delete**, **Download**.
- Multi-select with bulk **Delete** and **Download**.
- **Upload** images from a `.tar`, `.tar.gz`/`.tgz`, or `.tar.xz` archive.
- Downloads are streamed and compressed as `.tar.xz`.

## Requirements

The host running the tool must have:

- **Node.js >= 18**
- `tar`, `xz`, and `gzip` on `PATH`
- A container engine: **`docker`** (preferred) or **`crictl`**

When the engine is `crictl`, image **download/upload** additionally require
containerd's **`ctr`** binary (used as `ctr -n k8s.io images export/import`).
Without `ctr`, listing/details/delete still work but download/upload are
disabled.

The tool detects all of the above at startup and exits with a helpful message
if a hard prerequisite is missing.

## Usage

```sh
npm start
```

Then open http://127.0.0.1:3000.

Configuration via environment variables:

- `PORT` — listening port (default `3000`)
- `HOST` — bind address (default `127.0.0.1`)

> Note: the server ships without authentication and is intended to run on a
> trusted/local network. Do not expose it directly to untrusted clients.

## Tests

```sh
npm test
```

## Project layout

- `server.js` — `node:http` server, routing, streaming download/upload.
- `lib/cli.js` — prerequisite checks and engine/`ctr` detection.
- `lib/images.js` — list/inspect/delete/export/import per engine.
- `public/` — static web UI (`index.html`, `styles.css`, `app.js`).
