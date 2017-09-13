package org.springframework.security.web.server.context

import org.springframework.security.core.context.SecurityContext
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

import java.util.Optional

class ServerWebExchangeAttributeSecurityContextRepositoryFix : SecurityContextRepository {

    internal val ATTR = "USER"

    override fun save(exchange: ServerWebExchange, context: SecurityContext): Mono<ServerWebExchange> {
        exchange.attributes.put(ATTR, context)
        return Mono.just(SecurityContextRepositoryServerWebExchange(exchange, this))
    }

    override fun load(exchange: ServerWebExchange) = Mono.justOrEmpty(
            Optional.ofNullable(exchange.getAttribute<SecurityContext>(ATTR))
    )

}
