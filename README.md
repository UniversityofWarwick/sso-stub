# SSO Stub

This repo contains a simple stub Single Sign-on server for local application development. The aim is to make working with
ITS web applications (e.g. [Tabula](https://github.com/UniversityofWarwick/tabula)) painless.

## Getting started

Copy _conf/application.conf.example_ to _conf/application.conf_ and edit the cookie attributes as appropriate.

This application ships with Docker support. To build, tag and run a local container image, perform the following steps:

```
 $ ./buildDocker.sh
 $ docker run -p 127.0.0.1:8090:8080 sso-stub
```

In this example the app will be available on the host on port 8090 over HTTP - i.e. `http://localhost:8090`. You can also forward port 8443 if you want HTTPS.

To start the development server locally (without using Docker) on ports 8090 and 8443 (HTTP and self-signed auto TLS respectively) you can instead execute the `run.sh` script:

```
$ ./run.sh
```

<details>
<summary>System requirements</summary>
Pre-requisites: working NPM and node (LTS is fine)

Supported platforms: macOS, Linux

</details>

The homepage should be accessible at `https://localhost:8443`.

Next steps
----------

Visit the homepage and read the instructions on configuring your app's sso-config file.
