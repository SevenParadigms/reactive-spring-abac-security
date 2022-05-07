package io.github.sevenparadigms.abac.security.context

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.Constants.AUTHORIZE_IP
import io.github.sevenparadigms.abac.Constants.REQUEST
import io.github.sevenparadigms.abac.Constants.RESPONSE
import io.github.sevenparadigms.abac.security.auth.data.UserPrincipal
import io.github.sevenparadigms.abac.security.support.JwtCache
import org.springframework.http.HttpHeaders
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.userdetails.User
import org.springframework.util.MultiValueMap
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebSession
import reactor.core.publisher.Mono
import reactor.util.context.ContextView
import java.security.Principal

object ExchangeHolder {
    fun getSession(): Mono<WebSession> {
        return Mono.deferContextual { ctx: ContextView ->
            ctx.get(ServerWebExchange::class.java).session
        }
    }

    fun getToken(): Mono<String> {
        return Mono.deferContextual { ctx: ContextView ->
            Mono.just(
                (ctx.get(ServerWebExchange::class.java).request.headers.getFirst(HttpHeaders.AUTHORIZATION) as String)
                    .substring(Constants.BEARER.length)
            )
        }
    }

    fun getHeaders(): Mono<MultiValueMap<String, String>> {
        return Mono.deferContextual { ctx: ContextView ->
            Mono.just(
                ctx.get(ServerWebExchange::class.java).request.headers as MultiValueMap<String, String>
            )
        }
    }

    fun getRequest(): Mono<ServerHttpRequest> {
        return Mono.deferContextual { ctx: ContextView ->
            Mono.just(ctx.get(ServerWebExchange::class.java).attributes[REQUEST] as ServerHttpRequest)
        }
    }

    fun getResponse(): Mono<ServerHttpResponse> {
        return Mono.deferContextual { ctx: ContextView ->
            Mono.just(ctx.get(ServerWebExchange::class.java).attributes[RESPONSE] as ServerHttpResponse)
        }
    }

    fun getRemoteIp(): Mono<String> {
        return Mono.deferContextual { ctx: ContextView ->
            Mono.just(ctx.get(ServerWebExchange::class.java).attributes[AUTHORIZE_IP] as String)
        }
    }

    fun getUserPrincipal(): Mono<UserPrincipal> {
        return getToken().map { JwtCache.get(it)?.t1 }
    }

    fun getUser(): Mono<User> {
        return Mono.deferContextual { ctx: ContextView ->
            ctx.get(ServerWebExchange::class.java).getPrincipal<Principal>()
                .cast(UsernamePasswordAuthenticationToken::class.java)
                .map { it.principal }
                .cast(User::class.java)
        }
    }
}

