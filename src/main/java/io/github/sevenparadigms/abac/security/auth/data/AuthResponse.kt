package io.github.sevenparadigms.abac.security.auth.data

import com.fasterxml.jackson.annotation.JsonProperty
import java.io.Serializable

data class AuthResponse(
    @JsonProperty("token_type")
    var tokenType: String? = null,

    @JsonProperty("access_token")
    var accessToken: String? = null,

    @JsonProperty("expires_in")
    var expiresIn: Int? = null,

    @JsonProperty("refresh_token")
    var refreshToken: String? = null
) : Serializable