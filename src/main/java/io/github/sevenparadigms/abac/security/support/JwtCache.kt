package io.github.sevenparadigms.abac.security.support

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.Constants.JWT_CACHE_ACCESS
import io.github.sevenparadigms.abac.Constants.JWT_CACHE_WRITE
import io.github.sevenparadigms.abac.configuration.JwtProperties
import io.github.sevenparadigms.abac.security.auth.data.RevokeTokenEvent
import io.github.sevenparadigms.abac.security.auth.data.UserPrincipal
import org.apache.commons.codec.digest.MurmurHash2
import org.apache.commons.lang3.ObjectUtils
import org.apache.commons.lang3.StringUtils
import org.sevenparadigms.kotlin.common.info
import org.springframework.cache.Cache
import org.springframework.cache.CacheManager
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.r2dbc.repository.cache.CaffeineGuidedCacheManager
import org.springframework.data.r2dbc.support.Beans
import reactor.util.function.Tuple2
import reactor.util.function.Tuple3
import reactor.util.function.Tuples
import java.util.*

object JwtCache {
    private var cacheManager: CacheManager? = null
    private var jwtCache: Cache? = null
    private var refreshCache: Cache? = null

    fun put(key: String, principal: UserPrincipal, expireDate: Date, expired: Boolean = false) =
        put(MurmurHash2.hash64(key), principal, expireDate, expired)

    fun put(key: Long, principal: UserPrincipal, expireDate: Date, expired: Boolean = false) {
        evict(key)
        getJwtCache().put(key, Tuples.of(principal, expireDate, expired))
    }

    fun get(key: String): Tuple3<UserPrincipal, Date, Boolean>? = get(MurmurHash2.hash64(key))

    fun get(key: Long): Tuple3<UserPrincipal, Date, Boolean>? =
        getJwtCache().get(key, Tuple3::class.java) as Tuple3<UserPrincipal, Date, Boolean>?

    fun has(key: String): Boolean = get(key) != null

    fun has(key: Long): Boolean = get(key) != null

    fun evict(key: String) = evict(MurmurHash2.hash64(key))

    fun evict(key: Long): JwtCache {
        getJwtCache().evict(key)
        return this
    }

    fun revoke(key: Long): JwtCache {
        val eventPublisher = Beans.of(ApplicationEventPublisher::class.java)
        eventPublisher.publishEvent(RevokeTokenEvent(hash = key, source = this))
        return this
    }

    private fun getJwtCache(): Cache {
        if (cacheManager == null) {
            cacheManager = Beans.of(CacheManager::class.java, CaffeineGuidedCacheManager().apply {
                val expireAfterWrite = Beans.getProperty(JWT_CACHE_WRITE, StringUtils.EMPTY)
                val expireAfterAccess = Beans.getProperty(JWT_CACHE_ACCESS, StringUtils.EMPTY)
                if (expireAfterWrite.isEmpty() && expireAfterAccess.isEmpty()) {
                    val expiration = Beans.of(JwtProperties::class.java).expiration
                    if (ObjectUtils.isNotEmpty(expiration)) {
                        val timeout = expiration * 1000
                        setDefaultExpireAfterWrite(timeout)
                    } else {
                        setDefaultExpireAfterWrite(300000)
                    }
                }
            })
            info("ABAC Security initialize with cache: " + cacheManager!!.javaClass.simpleName)
            jwtCache = cacheManager!!.getCache(Constants.JWT_CACHE)
            refreshCache = cacheManager!!.getCache(Constants.JWT_CACHE_REFRESH)
        }
        return jwtCache!!
    }

    fun putRefresh(key: String, tokenHash: Long, expireDate: Date) {
        getJwtCache().put(MurmurHash2.hash64(key), Tuples.of(tokenHash, expireDate))
    }

    fun getRefresh(key: String): Tuple2<Long, Date>? {
        return getJwtCache().get(MurmurHash2.hash64(key), Tuple2::class.java) as Tuple2<Long, Date>?
    }

    fun evictRefresh(key: String) = evictRefresh(MurmurHash2.hash64(key))

    fun evictRefresh(key: Long): JwtCache {
        getJwtCache().evict(key)
        return this
    }
}