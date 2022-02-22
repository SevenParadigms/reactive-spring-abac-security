package io.github.sevenparadigms.abac.security.opaque.data

import java.util.*

data class TokenIntrospectionSuccessResponse(
    var status: TokenStatus? = null,
    var scope: HashSet<String>? = null,
    var tokenType: String? = null,
    var expiration: Date? = null,
    var issueTime: Date? = null,
    var notBeforeTime: Date? = null,
    var subject: String? = null,
    var audience: MutableList<String>? = null,
    var issuer: String? = null,
    var authorities: String? = null,
)