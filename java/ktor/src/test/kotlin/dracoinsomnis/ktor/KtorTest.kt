package dracoinsomnis.ktor

import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.http.parameters
import io.ktor.server.application.install
import io.ktor.server.application.plugin
import io.ktor.server.request.receiveParameters
import io.ktor.server.request.receiveText
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class KtorTest {
    private val ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
    private val attack = "/search?q=1%27%20union%20select%20password%20from%20users--%20"

    @Test
    fun plugin() = testApplication {
        val asked = mutableListOf<String>()
        application {
            install(DracoInsomnis) {
                options {
                    waf = "block"
                    isHeaders = true
                    review.secret = "owner-secret-0123456789"
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
        }
        val res = client.get("/") { header(HttpHeaders.UserAgent, ua) }
        assertEquals(200, res.status.value)
        assertEquals("page", res.bodyAsText())
        assertEquals("nosniff", res.headers["X-Content-Type-Options"])
        assertEquals(listOf("DENY"), client.get("/own") { header(HttpHeaders.UserAgent, ua) }.headers.getAll("X-Frame-Options"))

        // The app still reads every body.
        assertEquals("name=Ñandú", client.submitForm("/echo", parameters { append("name", "Ñandú") }).bodyAsText())
        assertEquals("json={\"name\": \"Ana\"}", client.post("/json") {
            contentType(ContentType.Application.Json)
            setBody("{\"name\": \"Ana\"}")
        }.bodyAsText())

        val blocked = client.get(attack) { header(HttpHeaders.UserAgent, ua) }
        val page = blocked.bodyAsText()
        assertEquals(403, blocked.status.value)
        assertFalse(page.contains("sqli"))
        assertEquals("no-store", blocked.headers[HttpHeaders.CacheControl])
        assertEquals(403, client.get("/.env").status.value)
        assertEquals(403, client.submitForm("/echo", parameters { append("message", "x'; DROP TABLE users; --") }).status.value)
        assertEquals(403, client.post("/json") {
            contentType(ContentType.Application.Json)
            setBody("{\"q\": \"' OR '1'='1\"}")
        }.status.value)

        val fields = Regex("type=\"hidden\" name=\"([a-z_]+)\" value=\"([^\"]*)\"").findAll(page).associate { it.groupValues[1] to it.groupValues[2] }
        val thanks = client.submitForm(attack, parameters {
            fields.forEach { (k, v) -> append(k, v) }
            append("draco_email", "ana@example.org")
            append("draco_message", "I was searching")
            append("draco_website", "")
        })
        assertEquals(200, thanks.status.value)
        assertTrue(thanks.bodyAsText().contains("Request sent"))
        assertEquals(listOf("ana@example.org"), asked)
    }
}
