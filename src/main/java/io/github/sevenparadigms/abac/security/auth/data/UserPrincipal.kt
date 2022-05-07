package io.github.sevenparadigms.abac.security.auth.data

import org.apache.commons.lang3.StringUtils
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import java.io.Serializable
import java.util.*

data class UserPrincipal(
    var id: UUID? = null,
    var login: String? = null,
    var password: String? = null,
    var authorities: List<String>? = null
) : Serializable

fun UserPrincipal.toUser() = User(login, password, authorities!!.map { SimpleGrantedAuthority(it) }.toList())

fun Authentication.toPrincipal() = UserPrincipal(
    id = credentials as UUID,
    login = name,
    password = StringUtils.EMPTY,
    authorities = authorities.map { it.authority }.toList()
)