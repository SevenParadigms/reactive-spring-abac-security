package io.github.sevenparadigms.abac.security.cache.service.impl

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.security.cache.exception.NotFoundInCacheException
import io.github.sevenparadigms.abac.security.cache.service.TokenCacheService
import io.github.sevenparadigms.abac.security.opaque.data.OpaqueTokenPrincipal
import io.github.sevenparadigms.abac.security.opaque.data.TokenStatus
import io.github.sevenparadigms.abac.security.opaque.encrypt.OpaqueTokenValidator
import org.springframework.cache.CacheManager
import reactor.core.publisher.Mono

class TokenCacheServiceImpl(
    private val validator: OpaqueTokenValidator,
    private val cacheManager: CacheManager,
) : TokenCacheService {

    // validate expire time
    override fun getTokenFromCache(token: String): Mono<OpaqueTokenPrincipal> {
        val cache = cacheManager.getCache(Constants.TOKEN_CACHE)!!
        val opaqueTokenPrincipal = cache.get(token, OpaqueTokenPrincipal::class.java)
            ?: return Mono.error(NotFoundInCacheException("Token must be in the cache"))
        return Mono.just(opaqueTokenPrincipal)
            .handle { it, sink ->
                if (it.status == TokenStatus.SUCCESS) {
                    opaqueTokenPrincipal.status = this.validator.expireValidateToken(opaqueTokenPrincipal)
                }
                cache.put(token, it)
                sink.next(opaqueTokenPrincipal)
            }
    }

    override fun putInCache(token: String, opaqueTokenPrincipal: OpaqueTokenPrincipal): Mono<OpaqueTokenPrincipal> {
        val cache = cacheManager.getCache(Constants.TOKEN_CACHE)!!
        return Mono.just(opaqueTokenPrincipal)
            .handle { it, sink ->
                cache.put(token, opaqueTokenPrincipal)
                sink.next(it)
            }
    }

    override fun revokeSyncToken(token: String) {
        val cache = cacheManager.getCache(Constants.TOKEN_CACHE)!!
        val cachedToken: OpaqueTokenPrincipal = cache.get(token, OpaqueTokenPrincipal::class.java)
            ?: throw NotFoundInCacheException("Token must be in the cache")

        cachedToken.status = TokenStatus.REVOKED
        cache.put(token, cachedToken)
    }
}