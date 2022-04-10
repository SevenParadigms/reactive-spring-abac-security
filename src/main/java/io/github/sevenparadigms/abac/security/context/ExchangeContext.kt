package io.github.sevenparadigms.abac.security.context

import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.configuration.JwtProperties
import kotlinx.coroutines.reactive.awaitFirst
import kotlinx.coroutines.runBlocking
import org.springframework.http.HttpHeaders
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Component
import org.springframework.util.MultiValueMap
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebSession
import java.time.Duration

@Component
class ExchangeContext(jwt: JwtProperties) {

    val attributes: Cache<String, ServerWebExchange> by lazy {
        CacheBuilder.newBuilder()
            .concurrencyLevel(Runtime.getRuntime().availableProcessors())
            .expireAfterWrite(Duration.ofSeconds(jwt.expiration))
            .build()
    }

    fun getSession(login: String): WebSession? {
        return runBlocking { attributes.getIfPresent(login)?.session?.awaitFirst() }
    }

    fun getToken(login: String): String? {
        return (attributes.getIfPresent(login)?.request?.headers?.getFirst(HttpHeaders.AUTHORIZATION) as String).substring(
            Constants.BEARER.length
        )
    }

    fun getHeaders(login: String): MultiValueMap<String, String>? {
        return attributes.getIfPresent(login)?.request?.headers as MultiValueMap<String, String>
    }

    fun getRequest(login: String): ServerHttpRequest? {
        return attributes.getIfPresent(login)?.attributes?.get(Constants.REQUEST) as ServerHttpRequest
    }

    fun getResponse(login: String): ServerHttpResponse? {
        return attributes.getIfPresent(login)?.attributes?.get(Constants.RESPONSE) as ServerHttpResponse
    }

    fun getRemoteIp(login: String): String? {
        return attributes.getIfPresent(login)?.attributes?.get(Constants.AUTHORIZE_IP) as String
    }

    fun getUser(login: String): User? {
        return attributes.getIfPresent(login)?.attributes?.get(Constants.PRINCIPAL) as User
    }
}