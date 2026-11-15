package e2e

import dracoinsomnis.DracoOptions
import dracoinsomnis.Gatekeeper
import dracoinsomnis.ktor.DracoInsomnis
import io.ktor.server.application.install
import io.ktor.server.application.plugin
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.request.receiveParameters
import io.ktor.server.request.receiveText
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlin.system.exitProcess

// Draco in real Ktor apps on Netty: one configured with options in the plugin block, one with a
// gatekeeper made in code (settings from the environment). Real sockets, real HTTP.

private const val UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
private const val ATTACK = "/search?q=1%27%20union%20select%20password%20from%20users--%20"
private const val FORM = "application/x-www-form-urlencoded"
private var fails = 0
private val http = HttpClient.newHttpClient()

private fun check(name: String, ok: Boolean) {
    println((if (ok) "ok   - " else "FAIL - ") + name)
    if (!ok) fails++
}

private fun send(method: String, url: String, type: String? = null, body: String? = null): HttpResponse<String> {
    val b = HttpRequest.newBuilder(URI.create(url)).header("User-Agent", UA)
    if (type != null) b.header("Content-Type", type)
    b.method(method, if (body == null) HttpRequest.BodyPublishers.noBody() else HttpRequest.BodyPublishers.ofString(body))
    return http.send(b.build(), HttpResponse.BodyHandlers.ofString())
}

private fun form(fields: Map<String, String>) =
    fields.entries.joinToString("&") { URLEncoder.encode(it.key, Charsets.UTF_8) + "=" + URLEncoder.encode(it.value, Charsets.UTF_8) }

fun main() {
    val secret = "owner-secret-0123456789"
    for (name in listOf("ktor netty (options)", "ktor netty (gatekeeper)")) {
        val asked = mutableListOf<String>()
        val server = embeddedServer(Netty, port = 0, host = "127.0.0.1") {
            install(DracoInsomnis) {
                if (name.endsWith("(options)")) {
                    options {
                        waf = "block"
                        isHeaders = true
                        review.secret = secret
                    }
                } else {
                    // As from the environment: DRACO_INSOMNIS_WAF=block and so on.
                    val o = DracoOptions.fromEnvironment(mapOf("PROXY" to "xff", "DRACO_INSOMNIS_WAF" to "block", "DRACO_INSOMNIS_HEADERS" to "1", "DRACO_INSOMNIS_REVIEW_SECRET" to secret))
                    gatekeeper = Gatekeeper(o)
                }
            }
            plugin(DracoInsomnis).gatekeeper.resolver(null).onReview { asked.add(it.email()) }
            routing {
                get("/") { call.respondText("page") }
                get("/own") {
                    call.response.header("X-Frame-Options", "DENY")
                    call.respondText("own")
                }
                get("/search") { call.respondText("results") }
                post("/echo") { call.respondText("name=" + call.receiveParameters()["name"]) }
                post("/json") { call.respondText("json=" + call.receiveText()) }
            }
        }.start(wait = false)
        val port = runBlocking { server.engine.resolvedConnectors().first().port }
        val url = "http://127.0.0.1:$port"
        try {
            val res = send("GET", "$url/")
            check("$name: an ordinary page passes", res.statusCode() == 200 && res.body() == "page")
            check("$name: security headers", res.headers().firstValue("X-Content-Type-Options").orElse("") == "nosniff")
            check("$name: the app's own header wins", send("GET", "$url/own").headers().allValues("X-Frame-Options") == listOf("DENY"))
            val echo = send("POST", "$url/echo", FORM, form(mapOf("name" to "Ñandú")))
            check("$name: the app still reads the form, in UTF-8", echo.statusCode() == 200 && echo.body() == "name=Ñandú")
            check("$name: the app still reads the JSON body", send("POST", "$url/json", "application/json", "{\"name\": \"Ana\"}").body() == "json={\"name\": \"Ana\"}")
            val blocked = send("GET", url + ATTACK)
            check("$name: SQL injection gets 403", blocked.statusCode() == 403)
            check("$name: the page never names the rule", !blocked.body().contains("sqli"))
            check("$name: .env probe gets 403", send("GET", "$url/.env").statusCode() == 403)
            check("$name: a posted form is inspected", send("POST", "$url/contact", FORM, form(mapOf("message" to "x'; DROP TABLE users; --"))).statusCode() == 403)
            check("$name: a JSON body is inspected", send("POST", "$url/json", "application/json", "{\"q\": \"' OR '1'='1\"}").statusCode() == 403)
            val fields = Regex("<input type=\"hidden\" name=\"([a-z_]+)\" value=\"([^\"]*)\">").findAll(blocked.body())
                .associate { it.groupValues[1] to it.groupValues[2] }.toMutableMap()
            fields["draco_email"] = "ana@example.org"
            fields["draco_message"] = "I was searching"
            fields["draco_website"] = ""
            val thanks = send("POST", url + ATTACK, FORM, form(fields))
            check("$name: the review request is thanked", thanks.statusCode() == 200 && thanks.body().contains("Request sent"))
            check("$name: and reaches the owner", asked == listOf("ana@example.org"))
        } finally {
            server.stop(100, 1000)
        }
    }
    println(if (fails == 0) "all passed (Draco Insomnis ${Gatekeeper.VERSION})" else "$fails failed")
    exitProcess(if (fails == 0) 0 else 1)
}
