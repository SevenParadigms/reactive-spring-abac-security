package io.github.sevenparadigms.abac.security.auth.data

import org.springframework.context.ApplicationEvent

class RevokeTokenEvent(
    internal val token: String,
    source: Any,
) : ApplicationEvent(source)
