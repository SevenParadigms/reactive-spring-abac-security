package io.github.sevenparadigms.abac.security.auth.data

import com.fasterxml.jackson.databind.JsonNode
import java.io.Serializable
import java.util.*

data class UserPrincipal(
    var id: UUID? = null,
    var login: String? = null,
    var password: String? = null,
    var authorities: JsonNode? = null
) : Serializable