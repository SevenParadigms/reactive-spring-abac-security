package io.github.sevenparadigms.abac.security.auth.data

import java.io.Serializable
import java.util.*

data class Authority(
    var id: UUID? = null,
    var name: String? = null
) : Serializable