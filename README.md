# Badgr Server

_Digital badge management for issuers, earners, and consumers_

Badgr-server is the Python/Django API backend for issuing [Open Badges](http://openbadges.org). In addition to a powerful Issuer API and browser-based user interface for issuing, Badgr offers integrated badge management and sharing for badge earners. Free accounts are hosted by Concentric Sky at [Badgr.com](http://info.badgr.com), but for complete control over your own issuing environment, Badgr Server is available open source as a Python/Django application.

See also [badgr-ui](https://github.com/concentricsky/badgr-ui), the front end written in Angular that serves as users' interface for this project.

## About the Badgr Project

Badgr was developed by [Concentric Sky](https://concentricsky.com), starting in 2015 to serve as an open source reference implementation of the Open Badges Specification. It provides functionality to issue portable, verifiable Open Badges as well as to allow users to manage badges they have been awarded by any issuer that uses this open data standard. Since 2015, Badgr has grown to be used by hundreds of educational institutions and other people and organizations worldwide. See [Project Homepage](https://badgr.org) for more details about contributing to and integrating with Badgr.

## Open Badges Implementation

Badgr-server hosts standard-compliant endpoints that implement the
[Open Badges 2.0 specification](https://openbadgespec.org). For each of the core Open Badges objects Issuer, BadgeClass
and Assertion, there is a standards-compliant public JSON endpoint handled by the Django application as well as an image
redirect path.

Each JSON endpoint, such as `/public/assertions/{entity_id}`, performs content negotiation. It will return a
standardized JSON-LD payload when the path is requested with no `Accept` header or when JSON payloads are requested.
Additionally, User-Agent detection allows bots attempting to render a preview card for social sharing to access a clean
HTML response that includes [Open Graph](https://ogp.me/) meta tags. Other clients requesting `text/html` will receive
a redirect to the corresponding public route on the UI application that runs in parallel to Badgr-server where humans
can be presented with a representation of the badge data in their browser.

Each image endpoint typically redirects to an image within the associated storage system. The system can convert from
SVG to PNG and adapt images to a common "wide" radio for the images needed for card-based previews in many social
network systems.

## How to get started on your local development environment.

Prerequisites:

-   Install docker (see [instructions](https://docs.docker.com/install/))
-   Install python
    -   Make sure you have the version(s) installed referenced in the [.pre-commit-config.yaml](.pre-commit-config.yaml)
    -   Also install `python-devel`, required to run the pre-commit hooks

### Setup your IDE/Editor

[Ruff](https://github.com/astral-sh/ruff) is used for linting and formatting.
It is providing an [LSP](https://github.com/astral-sh/ruff-lsp) for all editors supporting it.

_Note: For Visual Studio Code, the LSP is part of the extension and does not need to be installed separately._

#### Visual Studio Code

Setup is easiest with VS Code using the [recommended extensions](.vscode/extensions.json) [settings.default.json](.vscode/settings.default.json).
To install extensions look for "Extensions: Show Recommended Extensions" via the [Command Palette](https://code.visualstudio.com/docs/getstarted/userinterface#_command-palette) and install the highlighted extensions.

To set up your editor, copy the values from [settings.default.json](.vscode/settings.default.json) to your [User or Workspace (recommended) Settings](https://code.visualstudio.com/docs/configure/settings).
This will e.g. setup `ruff` as the default formatter and make sure linting works as expected.

### Copy local settings example file

Copy the example development settings:

-   `cp .docker/etc/settings_local.dev.py.example .docker/etc/settings_local.dev.py`

**NOTE**: you _may_ wish to copy and edit the production config. See Running the Django Server in "Production" below for more details.

-   `cp .docker/etc/settings_local.prod.py.example .docker/etc/settings_local.prod.py`

### Customize local settings to your environment

Edit the `settings_local.dev.py` and/or `settings_local.prod.py` to adjust the following settings:

-   Set `DEFAULT_FROM_EMAIL` to an address, for instance `"noreply@localhost"`
    -   The default `EMAIL_BACKEND= 'django.core.mail.backends.console.EmailBackend'` will log email content to console, which is often adequate for development. Other options are available. See Django docs for [sending email](https://docs.djangoproject.com/en/1.11/topics/email/).
-   Set `SECRET_KEY` and `UNSUBSCRIBE_SECRET_KEY` each to (different) cryptographically secure random values.
    -   Generate values with: `python -c "import base64; import os; print(base64.b64encode(os.urandom(30)).decode('utf-8'))"`
    -   Remove that part `.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(40))` to prevent issues with the admin panel login
-   Set `AUTHCODE_SECRET_KEY` to a 32 byte url-safe base64-encoded random string. This key is used for symmetrical encryption of authentication tokens. If not defined, services like OAuth will not work.
    -   Generate a value with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key())"`
-   Set `FIELD_ENCRYPTION_KEY` to a Fernet key. This key encrypts sensitive 2FA data (TOTP secrets) in the database. **This value must remain stable** — changing it makes existing 2FA secrets unreadable and will lock users out.
    -   Generate a value with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
    -   In production, set this via an environment variable or secrets manager, never hardcoded.

#### Additional configuration options

Set or adjust these values in your `settings_local.dev.py` and/or `settings_local.prod.py` file to further configure the application to your specific needs.

-   `HELP_EMAIL`:
    -   An email address for your support staff. The default is `help@badgr.io`.
-   `BADGR_APPROVED_ISSUERS_ONLY`:
    -   If you choose to use set this value to `True`, that means new user accounts will not be able to define new issuers (though they can be added as staff on issuers defined by others) unless they have the Django user permission 'issuer.add_issuer'. The recommended way to grant users this privilege is to create a group that grants it in the `/staff` admin area and addthe appropriate users to that group.
-   `PINGDOM_MONITORING_ID`:
    -   If you use [Pingdom](https://www.pingdom.com/) to monitor site performance, including this setting will embed Pingdom tracking script into the header.
-   `CELERY_ALWAYS_EAGER`:
    -   Setting this value to `True` causes Celery to immediately run tasks synchronously. Setting this value to `False` enables asynchronous processing using Celery workers, which can be used e.g. in the
        batch badge-awarding process. Celery is an asynchronous task runner built into Django and Badgr. Advanced deployments may separate celery workers from web nodes for improved performance. The default is `False`. When `CELERY_ALWAYS_EAGER=False`, ensure `CELERY_BROKER_URL` and `CELERY_RESULT_BACKEND` are properly configured (defaults to Redis at `redis://redis:6379/0`).
-   `OPEN_FOR_SIGNUP`:
    -   Allows you to turn off signup through the API by setting to `False` if you would like to use Badgr for only single-account use or to manually create all users in `/staff`. The default is `True` (signup API is enabled). UX is not well-supported in the `/staff` interface.
-   `DEFAULT_FILE_STORAGE` and `MEDIA_URL`:
    -   Django supports various backends for storing media, as applicable for your deployment strategy. See Django docs on the [file storage API](https://docs.djangoproject.com/en/1.11/ref/files/storage/)
-   `NOUNPROJECT_API_KEY` and `NOUNPROJECT_SECRET`:
    -   Set these values to be able to search for icons with in the badge creation process.
-   `AISKILLS_API_KEY` and `AISKILLS_ENDPOINT_CHATS`, `AISKILLS_ENDPOINT_KEYWORDS` and `AISKILLS_ENDPOINT_TREE`:
    -   Set these values to be able to get AI skill suggestions within the badge creation process.
-   `OIDC_RP_CLIENT_ID` and `OIDC_RP_CLIENT_SECRET`
    -   The credentials for the meinBildungsraum SSO connection
-   `OIDC_OP_AUTHORIZATION_ENDPOINT`, `OIDC_OP_TOKEN_ENDPOINT`, `OIDC_OP_USER_ENDPOINT`, `OIDC_OP_JWKS_ENDPOINT`, `OIDC_OP_END_SESSION_ENDPOINT`
    -   The endpoints for the meinBildungsraum SSO connection
    -   For the demo as specified [here](https://aai.demo.meinbildungsraum.de/realms/nbp-aai/.well-known/openid-configuration)
-   `LOGIN_BASE_URL`
    -   The base url for the redirect urls
    -   E.g. `http://localhost:4200/auth/login`
-   `LOGIN_REDIRECT_URL` and `LOGOUT_REDIRECT_URL`
    -   The redirect urls to our application after login / logout via meinBildungsraum
    -   After the login with meinBildungsraum, the OIDC session authentication needs to be converted to an access token
    -   This is done with the `auth/login?validateToken` url
    -   E.g. `http://localhost:4200/auth/login?validateToken` and `http://localhost:4200/auth/login`
    -   Typically you don't need to change these if you used the example with `LOGIN_BASE_URL`
-   `ALTCHA_API_KEY` and `ALTCHA_SECRET`:
    -   Set these values for captcha protection during the registration and issuer creation process. They can be obtained at [altcha.org](https://altcha.org/).
-   `WEBCOMPONENTS_ASSETS_PATH`:
    -   `badgr-ui` builds generate a range of web components that are used for our LTI integration. Set this to the URL of the folder that serves these webcomponents e.g. `https://mydomain.tld/webcomponents`

### Running the Django Server in Development

For development, it is usually best to run the project with the builtin django development server. The
development server will reload itself in the docker container whenever changes are made to the code in `apps/`.

To run the project with docker in a development mode:

-   `docker compose up`: build and get django and other components running
-   `docker compose exec api python manage.py migrate` - (while running) set up database tables
-   `docker compose exec api python manage.py dist` - generate docs swagger file(s)
-   `docker compose exec api python manage.py collectstatic` - Put built front-end assets into the static directory (Admin panel CSS, swagger docs).
-   `docker compose exec api python manage.py createsuperuser` - follow prompts to create your first admin user account

### Running the Django Server in "Production"

By default `docker compose` will look for a `docker-compose.yml` for instructions of what to do. This file
is the development (and thus default) config for `docker compose`.

If you'd like to run the project with a more production-like setup, you can specify the `docker-compose.prod.yml`
file. This setup **copies** the project code in (instead of mirroring) and uses nginx with uwsgi to run django.

-   `docker compose -f docker-compose.prod.yml up -d` - build and get django and other components (production mode)

-   `docker compose -f docker-compose.prod.yml exec api python manage.py migrate` - (while running) set up database tables

If you are using the production setup and you have made changes you wish to see reflected in the running container,
you will need to stop and then rebuild the production containers:

-   `docker compose -f docker-compose.prod.yml build` - (re)build the production containers

-   If the extension urls aren't adjusted (or the url changes, or for some other reason it seems as if extension schemas can't be loaded, e.g. because of 401 errors in the badge creation process), run the script in `scripts/change-extension-url.sh`.

#### Deployment

Checkout `deployment.md`

### Accessing the Django Server Running in Docker

The development server will be reachable on port `8000`:

-   http://localhost:8000/ (development)

The production server will be reachable on port `8080`:

-   http://localhost:8080/ (production)

Note: An error message when accessing the above mentioned URLs is perfectly fine, since the server doesn't actually serve anything on the root url.

There are various examples of URLs in this readme and they all feature the development port. You will
need to adjust that if you are using the production server.

### First Time Setup

-   Sign in to http://localhost:8000/staff/
-   Add an `EmailAddress` object for your superuser. [Edit your super user](http://localhost:8000/staff/badgeuser/badgeuser/1/change/)
-   Add an initial `TermsVersion` object

#### Badgr App Configuration

-   Sign in to http://localhost:8000/staff
-   View the "Badgr app" records and use the staff admin forms to create a BadgrApp. BadgrApp(s) describe the configuration that badgr-server needs to know about an associated installation of badgr-ui.

If your [badgr-ui](https://github.com/concentricsky/badgr-ui) is running on http://localhost:4000, use the following values:

-   CORS: ensure this setting matches the domain on which you are running badgr-ui, including the port if other than the standard HTTP or HTTPS ports. `localhost:4000`
-   Oauth authorization redirect: `http://localhost:4000/`
-   Signup redirect: `http://localhost:4000/signup/`
-   Email confirmation redirect: `http://localhost:4000/auth/login/`
-   Forgot password redirect: `http://localhost:4000/change-password/`
-   UI login redirect: `http://localhost:4000/auth/login/`
-   UI signup success redirect: `http://localhost:4000/signup/success/`
-   UI signup failure redirect: `http://localhost:4000/signup/failure/`
-   UI connect success redirect: `http://localhost:4000/profile/`
-   Public pages redirect: `http://localhost:4000/public/`

#### Authentication Configuration

-   [Create an OAuth2 Provider Application](http://localhost:8000/staff/oauth2_provider/application/add/) for the Badgr-UI to use with
    -   Client id: `public`
    -   Client type: Public
    -   allowed scopes: `rw:profile rw:issuer rw:backpack`
    -   Authorization grant type: Resource owner password-based
    -   Name: `Badgr UI`
    -   Redirect uris: blank (for Resource owner password-based. You can use this to set up additional OAuth applications that use authorization code token grants as well.)

#### OIDC authentication

If you set up the _Additional configuration options_ (or at least the parts relevant for OIDC authentication), you shouldn't have to configure anything else; the "Anmelden mit Mein Bildungsraum" button should work out of the box.
Do note that the OIDC authentication mechanism produces access tokens that, in contrast to the ones we generate ourselves, aren't restricted to any scopes.
They can thus access anything on the page not limited to admin / superuser users. This also is the default behavior for the tokens we generate ourselves.

### Run the tests

For the tests to run you first need to run docker (`docker compose up`).
Then within docker, run `tox`: `docker compose exec api tox`.
Note that you might have to run `docker compose build` once for the new changes to the testing enviornment to take effect.
To just run a single test:

```bash
docker compose exec api python /badgr_server/manage.py test -k <test-name>
# Example:
docker compose exec api python /badgr_server/manage.py test issuer.tests.test_issuer.IssuerTests.test_cant_create_issuer_with_unverified_email_v1
```

### Debug

For debugging, in the `Dockerfile.debug.api` `debugpy` is also installed and there is the docker compose file `docker-compose.debug.yml`.
In VSCode you can create a `launch.json` by choosing `Python` as debugger and `Remote Attach` as debug configuration (and defaults for the rest).
You can then start the application with

```bash
docker compose -f docker-compose.debug.yml up
```

and attach the debugger in VSCode by selecting _Python: Remote Attach_.
This process is heavily inspired by [this tutorial](https://dev.to/ferkarchiloff/how-to-debug-django-inside-a-docker-container-with-vscode-4ef9).

### Install and run Badgr UI {#badgr-ui}

Start in your `badgr` directory and clone badgr-ui source code: `git clone https://github.com/concentricsky/badgr-ui.git badgr-ui`

For more details view the Readme for [Badgr UI](https://github.com/concentricsky/badgr-ui).

### Code Quality

To ensure consistency and quality in code contributions, we use pre-commit hooks to adhere to commit message conventions and code quality guidelines. Follow these steps to set up your development environment:

-   Install Pre-commit

Make sure you have `pre-commit` installed on your machine. You can install it using pip:

```bash
pip install pre-commit
```

-   Initialize Pre-commit Hooks

Navigate to the root directory of the repository and run the following command to initialize pre-commit hooks:

```bash
pre-commit install
```

This command sets up the pre-commit hooks defined in the `pre-commit-config.yaml` file.

To run the configured hooks on some / all files of the project run:

```bash
pre-commit run --files <file-name>
pre-commit run --all-files
```

You will also need to have `commitizen` installed, e.g. via

```bash
pip install commitizen
```

## Branches

Development happens in feature branches (e.g. `feat/foo` or `fix/bar`). Those are then merged (via a PR) into `develop`. The `develop` branch is synchronized automatically with `develop.openbadges.education`. Once dev tests have completed on `develop.openbadges.education`, `develop` is merged (via a PR) into `main`. The `main` branch is synchronized automatically with `staging.openbadges.education`. Once this state is ready for a deployment, `main` is merged (via a PR) into `production`. The `production` branch is synchronized automatically with `openbadges.education`.

## API Documentation

This project includes an automatically generated API documentation using [drf-spectacular](https://drf-spectacular.readthedocs.io/).

You can access it at:

- **Swagger UI:** `/docs/`
- **Redoc:** `/redoc/`
- **OpenAPI schema (JSON):** `/api/schema/`

