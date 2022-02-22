package io.github.sevenparadigms.abac.security.cache.data

import org.springframework.context.ApplicationEvent

class RevokeTokenEvent(
    internal val token: String,
    source: Any,
) : ApplicationEvent(source)
