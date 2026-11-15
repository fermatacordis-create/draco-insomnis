package dracoinsomnis.ktor

import dracoinsomnis.DracoOptions
import dracoinsomnis.DracoRequest
import dracoinsomnis.Gatekeeper
import dracoinsomnis.Http
import dracoinsomnis.Json
import dracoinsomnis.Net
import dracoinsomnis.Store
import dracoinsomnis.Waf
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.BaseApplicationPlugin
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.application.pluginOrNull
import io.ktor.server.plugins.doublereceive.DoubleReceive
import io.ktor.server.request.httpMethod
import io.ktor.server.request.receiveText
import io.ktor.server.request.uri
import io.ktor.server.response.ApplicationSendPipeline
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.util.AttributeKey
import io.ktor.util.pipeline.PipelinePhase

/** Settings of the plugin: the options, or a gatekeeper made elsewhere (shared store, callbacks). */
class DracoInsomnisConfig {
    /** Every setting; see [DracoOptions]. */
    var options: DracoOptions = DracoOptions()

    /** Shared counters and block list (e.g. on Redis); null = this process only. */
    var store: Store? = null

    /** A ready gatekeeper; when set, [options] and [store] are not used. */
    var gatekeeper: Gatekeeper? = null

    /** `options { waf = "block"; headers = true; review.secret = "..." }` */
    fun options(configure: DracoOptions.() -> Unit) {
        options.configure()
    }
}

/**
 * Draco as a Ktor 3 plugin: `install(DracoInsomnis) { options { waf = "block" } }`. It answers before
 * routing; the app only sees what it lets through. Forms and JSON bodies up to 64 KB are inspected
 * and stay readable (it installs Ktor's DoubleReceive when the app has not).
 */
class DracoInsomnis private constructor(val gatekeeper: Gatekeeper) {
    companion object Plugin : BaseApplicationPlugin<Application, DracoInsomnisConfig, DracoInsomnis> {
        override val key = AttributeKey<DracoInsomnis>("DracoInsomnis")
        private val answered = AttributeKey<Boolean>("DracoInsomnisAnswered")
        private const val MAX_BODY = 65536L
        private val log = System.getLogger("DracoInsomnis")

        override fun install(pipeline: Application, configure: DracoInsomnisConfig.() -> Unit): DracoInsomnis {
            val config = DracoInsomnisConfig().apply(configure)
            val gate = config.gatekeeper ?: Gatekeeper(config.options, config.store).also {
                if (config.options.isLogEvents) it.logToSystemLogger()
            }
            if (pipeline.pluginOrNull(DoubleReceive) == null) pipeline.install(DoubleReceive)
            // Its own phase, before every other plugin (authentication, sessions, routing).
            val phase = PipelinePhase("DracoInsomnis")
            pipeline.insertPhaseBefore(ApplicationCallPipeline.Plugins, phase)
            pipeline.intercept(phase) {
                val answer = try {
                    gate.decide(read(call))
                } catch (e: Exception) {
                    // If Draco itself fails, the request goes through.
                    log.log(System.Logger.Level.WARNING, "Draco Insomnis could not inspect the request; it was let through", e)
                    null
                }
                if (answer != null) {
                    val out = gate.render(answer)
                    call.attributes.put(answered, true)
                    var type = ContentType.Text.Html
                    for (h in out.headers()) {
                        if (h.key.equals(HttpHeaders.ContentType, ignoreCase = true)) type = ContentType.parse(h.value)
                        else call.response.header(h.key, h.value)
                    }
                    call.respondText(out.body(), type, HttpStatusCode.fromValue(out.status()))
                    finish()
                }
            }
            // Added as the answer leaves, after the app set its own, so the app's always win.
            pipeline.sendPipeline.intercept(ApplicationSendPipeline.After) {
                if (call.attributes.getOrNull(answered) == true) return@intercept
                for (h in gate.securityHeaders(call.request.local.scheme == "https")) {
                    if (call.response.headers[h.key] == null) call.response.header(h.key, h.value)
                }
            }
            return DracoInsomnis(gate)
        }

        /** Reads a request the way Draco needs it. */
        suspend fun read(call: ApplicationCall): DracoRequest {
            val r = call.request
            val method = r.httpMethod.value.uppercase()
            val uri = r.uri
            val q = uri.indexOf('?')
            val rawPath = if (q < 0) uri else uri.substring(0, q)
            val rawQuery = if (q < 0) "" else uri.substring(q + 1)
            val params = ArrayList(Waf.flatten(Http.parseQuery(rawQuery)))
            var form: Map<String, String> = emptyMap()
            val kind = (r.headers[HttpHeaders.ContentType] ?: "").lowercase()
            val length = r.headers[HttpHeaders.ContentLength]?.toLongOrNull() ?: -1L
            val json = kind.contains("json")
            val urlencoded = kind.contains("x-www-form-urlencoded")
            if (method in setOf("POST", "PUT", "PATCH") && length in 0..MAX_BODY && (json || urlencoded)) {
                val text = call.receiveText()
                if (json) {
                    try {
                        val parsed = Json.parse(text)
                        params.addAll(Waf.flatten(parsed))
                        form = Http.jsonFields(parsed)
                    } catch (e: IllegalArgumentException) {
                        params.add(text)
                    }
                } else {
                    val values = Http.parseQuery(text)
                    params.addAll(Waf.flatten(values))
                    form = Http.lastValues(values)
                }
            }
            val remote = r.local.remoteAddress
            val unmapped = Net.unmap(remote.trim())
            // Cloudflare's country header, only when the connection really comes from Cloudflare.
            val country = if (Net.isIp(unmapped) && Net.contains(Net.CLOUDFLARE, unmapped)) r.headers["CF-IPCountry"] ?: "" else ""
            return DracoRequest().method(method).path(Http.decode(rawPath, false)).query(Http.decode(rawQuery, true)).params(params)
                .userAgent(r.headers[HttpHeaders.UserAgent]).remoteAddr(remote).country(country)
                .cfConnectingIp(r.headers["CF-Connecting-IP"]).forwardedFor((r.headers.getAll("X-Forwarded-For") ?: emptyList()).joinToString(", "))
                .accept(r.headers[HttpHeaders.Accept]).ajax("XMLHttpRequest".equals(r.headers["X-Requested-With"], ignoreCase = true)).form(form)
        }
    }
}
