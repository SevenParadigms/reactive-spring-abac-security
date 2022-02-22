package io.github.sevenparadigms.abac.security.support.model

import org.springframework.context.ApplicationContext
import org.springframework.context.i18n.LocaleContext
import org.springframework.http.codec.multipart.Part
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.util.MultiValueMap
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebSession
import reactor.core.publisher.Mono
import java.security.Principal
import java.time.Instant
import java.util.function.Function

class ServerWebExchangeImpl : ServerWebExchange {

    val attributes = HashMap<String, Any>()

    override fun getRequest(): ServerHttpRequest {
        TODO("Not yet implemented")
    }

    override fun getResponse(): ServerHttpResponse {
        TODO("Not yet implemented")
    }

    override fun getAttributes(): MutableMap<String, Any> {
        return attributes
    }

    override fun getSession(): Mono<WebSession> {
        return Mono.empty()
    }

    override fun <T : Principal?> getPrincipal(): Mono<T> {
        TODO("Not yet implemented")
    }

    override fun getFormData(): Mono<MultiValueMap<String, String>> {
        TODO("Not yet implemented")
    }

    override fun getMultipartData(): Mono<MultiValueMap<String, Part>> {
        TODO("Not yet implemented")
    }

    override fun getLocaleContext(): LocaleContext {
        TODO("Not yet implemented")
    }

    override fun getApplicationContext(): ApplicationContext? {
        TODO("Not yet implemented")
    }

    override fun isNotModified(): Boolean {
        TODO("Not yet implemented")
    }

    override fun checkNotModified(lastModified: Instant): Boolean {
        TODO("Not yet implemented")
    }

    override fun checkNotModified(etag: String): Boolean {
        TODO("Not yet implemented")
    }

    override fun checkNotModified(etag: String?, lastModified: Instant): Boolean {
        TODO("Not yet implemented")
    }

    override fun transformUrl(url: String): String {
        TODO("Not yet implemented")
    }

    override fun addUrlTransformer(transformer: Function<String, String>) {
        TODO("Not yet implemented")
    }

    override fun getLogPrefix(): String {
        TODO("Not yet implemented")
    }
}