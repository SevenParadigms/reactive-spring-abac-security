package io.github.sevenparadigms.abac.security.cache.listener

import io.github.sevenparadigms.abac.security.cache.data.RevokeTokenEvent
import io.github.sevenparadigms.abac.security.cache.service.TokenCacheService
import org.springframework.context.ApplicationListener

open class EventListenerImpl(
    private val cacheService: TokenCacheService,
) : ApplicationListener<RevokeTokenEvent> {

    override fun onApplicationEvent(event: RevokeTokenEvent) {
        cacheService.revokeSyncToken(event.token)
    }

}