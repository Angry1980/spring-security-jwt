package org.springframework.security.web.server.context;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Optional;

public class ServerWebExchangeAttributeSecurityContextRepositoryFix implements SecurityContextRepository {

    final String ATTR = "USER";

    public Mono<ServerWebExchange> save(ServerWebExchange exchange, SecurityContext context) {
        exchange.getAttributes().put(ATTR, context);
        return Mono.just(new SecurityContextRepositoryServerWebExchange(exchange, this));
    }

    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        return Mono.justOrEmpty(Optional.ofNullable(exchange.getAttribute(ATTR)));
    }
}
