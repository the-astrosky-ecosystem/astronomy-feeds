# Astronomy feeds on Bluesky

This repo contains the Python code to run the Astronomy feeds on Bluesky, powered by [the AT Protocol SDK](https://atproto.blue). It's split up into four libraries in `src/`:

- `astrofeed_firehose` - an optimized multiprocess Python module for ingesting operations from the [Bluesky](https://bsky.app) firehose and adding them to a database.
- `astrofeed_server` - a Flask app for serving posts to Bluesky users from the database.
- `astrobot` - a moderation bot that allows for in-app moderation of the feeds, including signing up users.
- `astrofeed_lib` - a library of functions common to all three core services above, including the database and feed spec.

This module was originally based on MarshalX's [bluesky-feed-generator](https://github.com/MarshalX/bluesky-feed-generator), but includes some extra optimizations (although its main bottleneck is still Python multiprocessing overhead.)

## About the Astronomy feeds

The [Astronomy feeds](https://bsky.app/profile/emily.space/feed/astro) on [Bluesky](https://bsky.app/) are a set of 'custom algorithms' that collate astronomy content on Bluesky.

## Installing

1. Download the module with

```bash
git clone https://github.com/bluesky-astronomy/astronomy-feeds.git
```

2. Ensure that you have uv installed to manage Python (see the [development guide](https://github.com/bluesky-astronomy/development-guide))

3. uv automatically fetches dependencies when running the services, but you may want to do `uv sync --all-extras` to ensure it also installs any optional dev dependencies.

4. Running the `astrofeed_firehose` service requires that you have basic compile tools installed (used by [faster-fifo](https://github.com/alex-petrenko/faster-fifo)), which may also make it not work on platforms other than Linux. You may additionally need to do `sudo apt install --reinstall build-essential gcc g++`. (Most Linux distributions and Windows Subsystem for Linux come with these already installed, but YMMV.)

## Running the services

Running each service requires setting environment variables and running a single start command.

### astrofeed_firehose

1. Set up the environment variables:

**Mandatory:**

- `BLUESKY_DATABASE` - either a path to an SQLite development database (if `ASTROFEED_PRODUCTION` is false), or a connection string for a remote MySQL database (if `ASTROFEED_PRODUCTION` is true.) The MySQL database connection string should have the format `mysql://USER:PASSWORD@HOST:PORT/NAME?ssl-mode=REQUIRED`.

**Mandatory in production:**

- `ASTROFEED_PRODUCTION` - set to True to instead connect to a remote MySQL database

**Optional settings:**

- `FIREHOSE_WORKER_COUNT` - number of post-processing workers. Defaults to your number of CPU cores; in general, setting this higher than ~2-4 isn't necessary, although it depends a lot on the speed of the post-processing workers on your machine.
- `FIREHOSE_BASE_URI` - websocket to fetch posts from. Defaults to `wss://bsky.network/xrpc`.
- `FIREHOSE_CURSOR_OVERRIDE` - cursor override to use when starting the firehose. Defaults to None, and it will instead fetch a cursor from the database. If the database cursor does not exist or is too old, the firehose will instead use the cursor of the latest Bluesky firehose commit.
- `ASTROFEED_DEBUG` - Enabled debug log output. Will require a restart of the service.

2. Start the service with the command `./run_firehose`, or with:

```bash
uv run -m astrofeed_firehose
```

### astrofeed_server

1. Set up the environment variables:

**Mandatory:**

- `BLUESKY_DATABASE` - either a path to an SQLite development database (if `ASTROFEED_PRODUCTION` is false), or a connection string for a remote MySQL database (if `ASTROFEED_PRODUCTION` is true.) The MySQL database connection string should have the format `mysql://USER:PASSWORD@HOST:PORT/NAME?ssl-mode=REQUIRED`.

**Mandatory in production:**

- `ASTROFEED_PRODUCTION` - set to True to instead connect to a remote MySQL database
- `ASTROFEED_DEV_TOKEN` - specifies a token used to download the developer database

**Optional settings:**

- `ASTROFEED_DEBUG` - Enabled debug log output. Will require a restart of the service.

2. Start the server with the command `./run_server`, or with:

```bash
uv run gunicorn --worker-tmp-dir /dev/shm src.astrofeed_server.app:app
```

### astrobot

1. Set up the environment variables:

**Mandatory:**

- `BLUESKY_DATABASE` - either a path to an SQLite development database (if `ASTROFEED_PRODUCTION` is false), or a connection string for a remote MySQL database (if `ASTROFEED_PRODUCTION` is true.) The MySQL database connection string should have the format `mysql://USER:PASSWORD@HOST:PORT/NAME?ssl-mode=REQUIRED`.
- `ASTROBOT_HANDLE` - the handle of the bot - should be set to `bot.astronomy.blue`.
- `ASTROBOT_PASSWORD` - the app password of the bot.

**Mandatory in production:**

- `ASTROFEED_PRODUCTION` - set to True to instead connect to a remote MySQL database

**Optional settings:**

- `ASTROFEED_DEBUG` - Enabled debug log output. Will require a restart of the service.

2. Start the bot with the command `./run_bot`, or with:

```bash
uv run -m astrobot
```

## Testing

There are a growing number of tests that help to ensure that the services are operating as expected (which, along with their supporting infrastructure, can be found in `astronomy-feeds/tests/`).

The tests are organized according to pytest discovery and operational practices. To run them, install pytest along with other project dependencies by running 
```bash
uv sync --extra dev
```
(or `uv sync --all-extras` to install everything extra), and then execute 
```bash
uv run pytest
```
in the `astronomy-feeds` directory.

The test infrastructure is built to use a PostgreSQL server running in a docker container, as specified elsewhere in the documentation and onboarding material. At present, it also requires the use of a local PostgreSQL client application (for access to the `pg_dump` command, specifically), and the version of this client application must be greater than or equal to the version of the server application in the Docker container. A check to ensure correct versioning is planned for a general-purpose "start dev environment" command that has yet to be implemented; for the time being, versions can manually be checked by running the following commands in a terminal:
```bash
sudo docker exec -it "<database name>" pg_dump --version
```
for the server version (with the "" included, and with \<database name\> replaced with the name of the target database), and
```bash
pg_dump --version
```
for the the local client version; and ensuring that the version of the server (first command) is lower than or equal to the version of the client (second command).
