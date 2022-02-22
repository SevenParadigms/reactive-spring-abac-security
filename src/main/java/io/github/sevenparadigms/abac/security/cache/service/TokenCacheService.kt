package io.github.sevenparadigms.abac.security.cache.service

import io.github.sevenparadigms.abac.security.opaque.data.OpaqueTokenPrincipal
import reactor.core.publisher.Mono

interface TokenCacheService {
    fun getTokenFromCache(token: String): Mono<OpaqueTokenPrincipal>
    fun putInCache(token: String, opaqueTokenPrincipal: OpaqueTokenPrincipal): Mono<OpaqueTokenPrincipal>
    fun revokeSyncToken(token: String)
}