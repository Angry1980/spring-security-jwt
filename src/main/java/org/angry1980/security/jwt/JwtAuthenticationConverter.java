package org.angry1980.security.jwt;

import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

public class JwtAuthenticationConverter implements Function<ServerWebExchange, Mono<Authentication>> {

    private static Logger LOG = LoggerFactory.getLogger(JwtAuthenticationConverter.class);

    private final String signingKey;

    public JwtAuthenticationConverter(String signingKey) {
        this.signingKey = Objects.requireNonNull(signingKey);
    }

    @Override
    public Mono<Authentication> apply(ServerWebExchange exchange) {
        return Mono.defer(() -> Optional.ofNullable(
                exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION)
            ).flatMap(list -> list.stream()
                .filter(it -> it.startsWith("Bearer "))
                .map(it -> it.substring(7))
                .findFirst()
            ).map(value -> {
                try {
                    return Jwts.parser().setSigningKey(signingKey).parseClaimsJws(value);
                } catch(Exception e) {
                    LOG.error("Error while parsing jwt token for {}", JwtUtils.getRequestInfo(exchange), e);
                }
                return null;
            }).map(JwtAuthenticationToken::new)
            .map(token -> Mono.just(token))
            .orElseGet(() -> Mono.empty())
        );
    }
}
