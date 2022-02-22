package io.github.sevenparadigms.abac.security.opaque

import io.github.sevenparadigms.abac.security.cache.service.TokenCacheService
import io.github.sevenparadigms.abac.security.opaque.data.OpaqueTokenPrincipal
import io.github.sevenparadigms.abac.security.opaque.data.TokenStatus
import io.github.sevenparadigms.abac.security.opaque.service.TokenIntrospectionService
import io.jsonwebtoken.Claims
import io.jsonwebtoken.JwtException
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector
import reactor.core.publisher.Mono
import java.lang.IllegalArgumentException

class ReactiveOpaqueTokenIntrospectorImpl(
    private val cacheService: TokenCacheService?,
    private val delegate: TokenIntrospectionService?,
) : ReactiveOpaqueTokenIntrospector {

    init {
        if (cacheService == null && delegate == null)
            throw IllegalArgumentException("Introspector must have cache or delegate introspector")
    }

    override fun introspect(token: String): Mono<OAuth2AuthenticatedPrincipal> {
        return Mono.just(token)
            .flatMap(this::getTokenFromCacheIfCacheEnabledOrIntrospect)
            .handle { it, sink ->
                if (it.status != TokenStatus.SUCCESS) {
                    sink.error(JwtException("JWT token status: ${it.status.name}"))
                } else {
                    sink.next(
                        DefaultOAuth2AuthenticatedPrincipal(
                            it.attributes[Claims.SUBJECT]!! as String,
                            it.attributes,
                            it.authorities
                        )
                    )
                }
            }
    }

    private fun delegateIntrospect(token: String): Mono<OpaqueTokenPrincipal> {
        return delegate!!.delegateIntrospect(token)
            .handle { it, sink ->
                if (cacheService != null) cacheService.putInCache(token, it)
                else sink.next(it)
            }
    }

    // if opaque enabled -> must be enabled cache or introspector
    private fun getTokenFromCacheIfCacheEnabledOrIntrospect(token: String): Mono<OpaqueTokenPrincipal> {
        return Mono.just(token)
            .flatMap {
                if (cacheService != null)
                    this.cacheService.getTokenFromCache(token)
                        .onErrorResume {
                            if (delegate == null) return@onErrorResume Mono.error(it)
                            this.delegateIntrospect(token)
                        }
                else this.delegateIntrospect(token)
            }
    }

}