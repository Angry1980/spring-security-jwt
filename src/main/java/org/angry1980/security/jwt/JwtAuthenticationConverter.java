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

/**
 *  Function which is used to get info for authentication from http request
 */
public class JwtAuthenticationConverter implements Function<ServerWebExchange, Mono<Authentication>> {

    private static Logger LOG = LoggerFactory.getLogger(JwtAuthenticationConverter.class);

    private final String signingKey;

    public JwtAuthenticationConverter(String signingKey) {
        this.signingKey = Objects.requireNonNull(signingKey);
    }

    @Override
    public Mono<Authentication> apply(ServerWebExchange exchange) {
        return Mono.defer(() -> Optional.ofNullable(
                // get values of Authorization header
                exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION)
            ).flatMap(list ->
                list.stream()
                    // choose the first one which starts with token type prefix
                    .filter(value -> value.startsWith("Bearer "))
                    // get value of token
                    .map(value -> value.substring(7))
                    .findFirst()
            ).map(value -> {
                try {
                    // parse string value to signed json web token
                    return Jwts.parser().setSigningKey(signingKey).parseClaimsJws(value);
                } catch(Exception e) {
                    LOG.error("Error while parsing jwt token for {}", JwtUtils.getRequestInfo(exchange), e);
                }
                return null;
            })
            // wrap parsed jwt by object which implements spring Authentication interface
            .map(JwtAuthenticationToken::new)
            .map(token -> Mono.just(token))
            .orElseGet(() -> Mono.empty())
        );
    }
}
