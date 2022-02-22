package io.github.sevenparadigms.abac.security.cache

import io.github.sevenparadigms.abac.Constants
import org.springframework.cache.Cache
import org.springframework.cache.CacheManager
import java.util.*

class TokenCacheManager(expiration: String) : CacheManager {

    private val cacheMap: MutableMap<String, TokenCache> =
        Collections.singletonMap(Constants.TOKEN_CACHE, TokenCache(expiration.toLong()))

    override fun getCache(name: String): Cache? {
        return if (name in cacheMap) {
            cacheMap[name]
        } else {
            cacheMap[Constants.TOKEN_CACHE]
        }
    }

    override fun getCacheNames(): MutableCollection<String> {
        return Collections.singletonList(Constants.TOKEN_CACHE)
    }

}