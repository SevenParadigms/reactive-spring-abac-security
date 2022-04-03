package io.github.sevenparadigms.abac.configuration

import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame
import io.netty.handler.timeout.IdleStateEvent
import io.netty.handler.timeout.IdleStateHandler
import io.netty.handler.timeout.ReadTimeoutException
import io.netty.handler.timeout.WriteTimeoutException
import org.springframework.boot.web.embedded.netty.NettyReactiveWebServerFactory
import org.springframework.boot.web.embedded.netty.NettyServerCustomizer
import org.springframework.boot.web.server.WebServerFactoryCustomizer
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.r2dbc.support.JsonUtils
import org.springframework.http.codec.ServerCodecConfigurer
import org.springframework.http.codec.json.Jackson2JsonDecoder
import org.springframework.http.codec.json.Jackson2JsonEncoder
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsWebFilter
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource
import org.springframework.web.reactive.config.WebFluxConfigurer
import org.springframework.web.server.session.WebSessionManager
import reactor.core.publisher.Mono
import reactor.netty.Connection
import reactor.netty.http.server.HttpServer


@Configuration
class WebFluxConfig : WebFluxConfigurer {
    override fun configureHttpMessageCodecs(configurer: ServerCodecConfigurer) {
        configurer.defaultCodecs().apply {
            jackson2JsonEncoder(Jackson2JsonEncoder(JsonUtils.getMapper()))
            jackson2JsonDecoder(Jackson2JsonDecoder(JsonUtils.getMapper()))
            maxInMemorySize(-1)
        }
    }

    @Bean
    fun webFilter(): CorsWebFilter {
        val configuration = CorsConfiguration().apply {
            allowedMethods = listOf("GET", "POST", "PUT", "DELETE", "OPTIONS")
            allowedOriginPatterns = listOf("*")
            allowedHeaders = listOf("*")
            maxAge = 3600L
            allowCredentials = true
        }
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration)
        return CorsWebFilter(source)
    }

    @Bean
    fun nettyWebServerFactoryCustomizer() = WebServerFactoryCustomizer<NettyReactiveWebServerFactory> {
        it.addServerCustomizers(
            NettyServerCustomizer { server: HttpServer ->
                server.doOnConnection { connection: Connection ->
                    connection.addHandlerFirst(
                        object : IdleStateHandler(0, 0, 0) {
                            override fun channelIdle(ctx: ChannelHandlerContext, evt: IdleStateEvent) {
                                ctx.fireExceptionCaught(
                                    if (evt.state() == IdleStateEvent.WRITER_IDLE_STATE_EVENT.state())
                                        WriteTimeoutException.INSTANCE
                                    else
                                        ReadTimeoutException.INSTANCE
                                )
                                ctx.write(CloseWebSocketFrame())
                                ctx.close()
                            }
                        }
                    )
                }
            }
        )
    }

    @Bean
    fun webSessionManager(): WebSessionManager = WebSessionManager { Mono.empty() }
}