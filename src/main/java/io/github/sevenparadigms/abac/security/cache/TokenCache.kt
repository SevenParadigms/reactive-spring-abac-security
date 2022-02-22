package io.github.sevenparadigms.abac.security.cache

import com.google.common.cache.CacheBuilder
import io.github.sevenparadigms.abac.Constants
import org.springframework.cache.Cache
import org.springframework.cache.support.AbstractValueAdaptingCache
import java.time.Duration
import java.util.concurrent.Callable

class TokenCache(
    expiration: Long
) : AbstractValueAdaptingCache(false) {

    private val name: String = Constants.TOKEN_CACHE
    private val store: com.google.common.cache.Cache<Any, Any> = CacheBuilder.newBuilder()
        .concurrencyLevel(Runtime.getRuntime().availableProcessors())
        .expireAfterWrite(Duration.ofSeconds(expiration))
        .build()

    override fun getName(): String {
        return this.name
    }

    override fun getNativeCache(): Any {
        return this.store
    }

    @Suppress("UNCHECKED_CAST")
    override fun <T : Any?> get(key: Any, valueLoader: Callable<T>): T? {
        return this.fromStoreValue(this.store.get(key) {
            {
                try {
                    this.toStoreValue(valueLoader.call())
                } catch (var5: Throwable) {
                    throw Cache.ValueRetrievalException(key, valueLoader, var5)
                }
            }
        }
        ) as T
    }

    override fun put(key: Any, value: Any?) {
        this.store.put(key, this.toStoreValue(value))
    }

    override fun evict(key: Any) {
        this.store.invalidate(key)
    }

    override fun clear() {
        this.store.invalidateAll()
    }

    override fun lookup(key: Any): Any? {
        return this.store.getIfPresent(key)
    }
}