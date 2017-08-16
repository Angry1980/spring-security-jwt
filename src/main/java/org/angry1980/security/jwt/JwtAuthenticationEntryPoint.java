package org.angry1980.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.AuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static Logger LOG = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);

    @Override
    public <T> Mono<T> commence(ServerWebExchange exchange, AuthenticationException e) {
        LOG.info("Error while handling {}: {}", JwtUtils.getRequestInfo(exchange), e.getMessage());
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return Mono.empty();
    }
}
