# Draco Insomnis for Java and Kotlin

The Draco Insomnis firewall for the JVM (Java 17 or newer), with **no dependencies**:

- `draco-insomnis-X.jar`: the engine and a **Jakarta Servlet filter** for Spring Boot 3 and 4 (Spring
  MVC), Tomcat 10.1+, Jetty 12, Undertow and any Jakarta EE 10 server (WildFly, Payara, Open Liberty).
- `draco-insomnis-ktor-X.jar`: a **Ktor 3** plugin for Kotlin (it needs the first jar).

Same signatures and limits as the WordPress, CMS, server, JavaScript, Python, Go, Ruby and .NET
editions; the Java engine runs the same shared test cases (`tests/vectors`).

Install the jars from the release into your local Maven repository (the pom inside each jar is
complete, so nothing else is needed):

```sh
mvn install:install-file -Dfile=draco-insomnis-X.jar
mvn install:install-file -Dfile=draco-insomnis-ktor-X.jar   # Ktor only
```

```xml
<dependency>
  <groupId>io.github.fermatacordis-create</groupId>
  <artifactId>draco-insomnis</artifactId>   <!-- or draco-insomnis-ktor -->
  <version>X</version>
</dependency>
```

Gradle: `implementation("io.github.fermatacordis-create:draco-insomnis:X")` with `mavenLocal()`.

## Spring Boot

```java
@Bean
@ConfigurationProperties("draco-insomnis")
DracoOptions dracoOptions() { return new DracoOptions(); }

@Bean
Gatekeeper dracoGatekeeper(DracoOptions options) { return new Gatekeeper(options).logToSystemLogger(); }

@Bean
FilterRegistrationBean<DracoFilter> dracoFilter(Gatekeeper gate) {
    var b = new FilterRegistrationBean<>(new DracoFilter(gate));
    b.setOrder(Ordered.HIGHEST_PRECEDENCE); // first, before Spring Security
    return b;
}
```

```properties
# application.properties
draco-insomnis.waf=block
draco-insomnis.pace=block
draco-insomnis.headers=true
```

## Any servlet container (web.xml)

```xml
<filter>
  <filter-name>draco</filter-name>
  <filter-class>dracoinsomnis.servlet.DracoFilter</filter-class>
  <init-param><param-name>waf</param-name><param-value>block</param-value></init-param>
  <init-param><param-name>headers</param-name><param-value>true</param-value></init-param>
</filter>
<filter-mapping><filter-name>draco</filter-name><url-pattern>/*</url-pattern></filter-mapping>
```

The init parameters are the option names below; lists are comma-separated (`adminIps`,
`geo.countries`). `DracoOptions.fromEnvironment()` reads `DRACO_INSOMNIS_WAF`, `DRACO_INSOMNIS_GEO_COUNTRIES`
and so on (only variables with that prefix).

## Ktor

```kotlin
install(DracoInsomnis) {
    options {
        waf = "block"
        pace = "block"
        isHeaders = true
    }
}
```

The plugin answers before routing, authentication and sessions. It installs Ktor's `DoubleReceive`
(when the app has not) so the app can still read the body Draco inspected.

## What it does

In this order: blocked addresses may read but not post or open sensitive pages (`/login`,
`/j_security_check`, `/oauth2/token`, ... or your own list); the country filter (behind Cloudflare
from its header, otherwise `geo.file`, a local list that downloads itself and is checked against its
published SHA-256); the firewall signatures (log or block; 5 attacks in 10 minutes block the address
for 7 days); the anti-copy pace limit (HTML pages only; Google, Bing, Apple and Yandex once the reverse
DNS proves them). Forms and JSON bodies up to 64 KB are read once and given back unchanged, so the app
reads them as before (forms without a charset are read as UTF-8). Security headers never replace the
app's own. If Draco itself fails, the request goes through.

| Option | Default | |
| --- | --- | --- |
| `waf` | `log` | `off`, `log` or `block` |
| `pace` | `off` | `off`, `log` or `block`; `rateIp`, `rateNet` (at least 10) |
| `proxy`, `trustedProxies` | connection | `cf` or `xff`, and who may set them |
| `adminIps`, `except`, `sensitive` | | never inspected; path prefixes never inspected; your own sensitive endings |
| `headers`, `hsts` | off | nosniff, frames, referrer, permissions; HSTS over HTTPS |
| `geo.*` | off | `mode` (`block` or `allow`), `countries`, `action` (`log` or `block`), `scope` (`sensitive` or `site`), `file` |
| `review.secret` | off | 16+ characters; requests reach `onReview` (and the log) |
| `crowdSec.url`, `crowdSec.apiKey` | off | the owner's CrowdSec Local API (`cscli bouncers add draco`) |
| `logEvents` | off | every line of evidence as JSON to the `DracoInsomnis` logger (`System.Logger`) |
| `texts.*` | English | the page texts, by key |

The counters and the block list live in memory (one process). For several servers, implement
`Store` (`bump`, `get`, `set`, `delete`) on Redis and pass it to `new Gatekeeper(options, store)`:
the keys are the same as in the other editions, so one Redis can serve apps in several languages.

`Gatekeeper` has `onEvent`, `onReview`, `blocks()` (add, remove, list) and `crowdSec().sync()`.

Not covered: Spring WebFlux and other non-servlet reactive stacks, and `javax.servlet` (Spring Boot 2).

## Building and tests

`bin/build-java.sh` builds both jars (reproducible; it needs only Docker when Maven is not
installed). `mvn test` in `java/` runs the engine, the shared vectors, the filter inside Jetty and
the Ktor plugin; `java/e2e/run.sh` runs the built jars inside real Spring Boot (Tomcat) and Ktor
(Netty) apps.
