package io.github.sevenparadigms.abac.security.context

import io.github.sevenparadigms.abac.Constants.AUTHORIZE_IP
import io.github.sevenparadigms.abac.Constants.PRINCIPAL
import io.github.sevenparadigms.abac.Constants.REQUEST
import io.github.sevenparadigms.abac.Constants.RESPONSE
import org.apache.commons.lang3.StringUtils
import org.springframework.http.HttpHeaders
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import reactor.util.context.Context

@Component
class ExchangeFilter(
    private val exchangeContext: ExchangeContext
) : WebFilter {
    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        exchange.attributes[REQUEST] = exchange.request
        exchange.attributes[RESPONSE] = exchange.response
        exchange.attributes[AUTHORIZE_IP] = exchange.request.headers.getFirst(AUTHORIZE_IP) ?: StringUtils.EMPTY

        if (exchange.request.headers.containsKey(HttpHeaders.AUTHORIZATION)) {
            return ReactiveSecurityContextHolder.getContext().flatMap {
                exchange.attributes[PRINCIPAL] = it.authentication.principal
                exchangeContext.attributes.put(it.authentication.name, exchange)
                chain.filter(exchange)
            }.contextWrite { context: Context -> context.put(ServerWebExchange::class.java, exchange) }
        }
        return chain.filter(exchange)
            .contextWrite { context: Context -> context.put(ServerWebExchange::class.java, exchange) }
    }
}