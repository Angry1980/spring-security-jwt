package org.angry1980.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.web.server.AuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.AccessDeniedHandler;
import org.springframework.security.web.server.authorization.HttpStatusAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Objects;

/**
 * Handler of authorization errors
 */
public class JwtExceptionTranslationWebFilter implements WebFilter {

    private static Logger LOG = LoggerFactory.getLogger(JwtExceptionTranslationWebFilter.class);

    private final AuthenticationEntryPoint entryPoint;
    private final AccessDeniedHandler accessDeniedHandler;

    public JwtExceptionTranslationWebFilter(AuthenticationEntryPoint entryPoint) {
        this(entryPoint, new HttpStatusAccessDeniedHandler(HttpStatus.FORBIDDEN));
    }

    public JwtExceptionTranslationWebFilter(AuthenticationEntryPoint entryPoint, AccessDeniedHandler accessDeniedHandler) {
        this.entryPoint = Objects.requireNonNull(entryPoint);
        this.accessDeniedHandler = Objects.requireNonNull(accessDeniedHandler);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return chain.filter(exchange)
                .onErrorResume(AccessDeniedException.class, e ->
                    exchange.getPrincipal()
                            // user was not authenticated
                            .switchIfEmpty(
                                    Mono.defer(
                                            () -> entryPoint.commence(exchange, new AuthenticationCredentialsNotFoundException("Not Authenticated", e))
                                    )
                            )
                            // user is authenticated but does not have enough rights to get access to resource
                            .flatMap( principal -> {
                                LOG.info("Access for {} to {} is denied", principal.getName(), JwtUtils.getRequestInfo(exchange));
                                return accessDeniedHandler.<Void>handle(exchange, e);
                            })
                );
    }
}
