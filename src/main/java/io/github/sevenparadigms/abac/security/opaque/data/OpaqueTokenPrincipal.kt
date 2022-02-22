package io.github.sevenparadigms.abac.security.opaque.data

import org.springframework.security.core.GrantedAuthority

data class OpaqueTokenPrincipal(
    var status: TokenStatus,
    val attributes: MutableMap<String, Any> = null ?: HashMap(),
    val authorities: MutableCollection<out GrantedAuthority>? = null,
)