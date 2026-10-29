# Prowler Reviewer

Review Prowler OCSF JSON (AWS, Azure, GCP) in the browser. There is one account. Scan data stays on this machine, and the site is reachable only at http://127.0.0.1:8081.

## Install

Git, Docker, and Docker Compose. The start command is `docker compose`, with a space.

### Ubuntu

```bash
sudo apt update
sudo apt install -y git docker.io docker-compose-v2
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Log out and back in so the `docker` group applies. `docker compose version` should print a version.

### Kali Linux

Install `docker.io`. The package named `docker` is a different program.

```bash
sudo apt update
sudo apt install -y git docker.io docker-compose
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Log out and back in. Skip the group step when you are already root. `docker compose version` should print a version.

If `docker` reports a permission error, log in again, or put `sudo` in front of the compose commands below.

## Start

From this directory:

```bash
docker compose up -d --build
```

Open http://127.0.0.1:8081. The first visit creates the account. The password must be at least 5 characters. Later visits ask you to sign in.

The first build downloads the Prowler compliance catalog and can take a few minutes. Later starts reuse the images:

```bash
docker compose up -d
```

`docker compose down` stops the app and keeps the data.

Upload a file from `prowler aws -M json-ocsf` (same `-M json-ocsf` flag for `azure` and `gcp`).

## Lost password

This is the break-glass recovery. Run it on the machine that has Docker, from this directory. It asks for a new password, does not echo it, and refuses a password passed as an argument. It replaces the stored hash, clears the sign-in lockout, and signs every session out.

```bash
docker compose exec -u root -it backend node reset-password.js
```

When there is no terminal, send the password on stdin:

```bash
docker compose exec -u root -T backend node reset-password.js --password-stdin
```

If no account exists yet, add `--username <name>`.
