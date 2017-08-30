package org.springframework.security.config.web.server;

import org.angry1980.security.jwt.JwtAuthenticationConverter;
import org.angry1980.security.jwt.JwtAuthenticationEntryPoint;
import org.angry1980.security.jwt.JwtAuthenticationProvider;
import org.angry1980.security.jwt.JwtExceptionTranslationWebFilter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerAdapter;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.web.server.AuthenticationEntryPoint;
import org.springframework.security.web.server.MatcherSecurityWebFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.DefaultAuthenticationSuccessHandler;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;
import org.springframework.security.web.server.authorization.DelegatingReactiveAuthorizationManager;
import org.springframework.security.web.server.context.SecurityContextRepository;
import org.springframework.security.web.server.context.SecurityContextRepositoryWebFilter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class HttpJwtSecurity {

    private String signingKey;

    private ServerWebExchangeMatcher securityMatcher = ServerWebExchangeMatchers.anyExchange();

    private AuthorizeExchangeBuilder authorizeExchangeBuilder;

    private HeaderBuilder headers = new HeaderBuilder();

    private Optional<SecurityContextRepository> securityContextRepository = Optional.empty();
    private List<AuthenticationProvider> authenticationProviders = Arrays.asList(new JwtAuthenticationProvider());

    public HttpJwtSecurity securityMatcher(ServerWebExchangeMatcher matcher) {
        this.securityMatcher = matcher;
        return this;
    }

    private ServerWebExchangeMatcher getSecurityMatcher() {
        return this.securityMatcher;
    }

    public HttpJwtSecurity securityContextRepository(SecurityContextRepository securityContextRepository) {
        Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
        this.securityContextRepository = Optional.of(securityContextRepository);
        return this;
    }

    public HeaderBuilder headers() {
        return headers;
    }

    public HttpJwtSecurity signingKey(String signingKey){
        this.signingKey = signingKey;
        return this;
    }

    public AuthorizeExchangeBuilder authorizeExchange() {
        if(authorizeExchangeBuilder == null) {
            authorizeExchangeBuilder = new AuthorizeExchangeBuilder();
        }
        return authorizeExchangeBuilder;
    }

    public SecurityWebFilterChain build() {
        AuthenticationEntryPoint entryPoint = new JwtAuthenticationEntryPoint();
        List<WebFilter> filters = new ArrayList<>();
        if(headers != null) {
            filters.add(headers.build());
        }
        securityContextRepositoryWebFilter().ifPresent( f-> filters.add(f));
        filters.add(authenticationFilter(entryPoint));
        if(authorizeExchangeBuilder != null) {
            filters.add(new JwtExceptionTranslationWebFilter(entryPoint));
            filters.add(authorizeExchangeBuilder.build());
        }
        return new MatcherSecurityWebFilterChain(getSecurityMatcher(), filters);
    }

    private AuthenticationWebFilter authenticationFilter(AuthenticationEntryPoint entryPoint){
        AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(new ReactiveAuthenticationManagerAdapter(
                new ProviderManager(authenticationProviders)
        ));
        authenticationFilter.setEntryPoint(entryPoint);
        if(signingKey != null){
            authenticationFilter.setAuthenticationConverter(new JwtAuthenticationConverter(signingKey));
        }
        DefaultAuthenticationSuccessHandler successHandler = new DefaultAuthenticationSuccessHandler();
        securityContextRepository.ifPresent(repository -> successHandler.setSecurityContextRepository(repository));
        authenticationFilter.setAuthenticationSuccessHandler(successHandler);
        return authenticationFilter;
    }

    private Optional<SecurityContextRepositoryWebFilter> securityContextRepositoryWebFilter() {
        return securityContextRepository
                .flatMap( r -> Optional.of(new SecurityContextRepositoryWebFilter(r)));
    }

    public static HttpJwtSecurity jwt() {
        return new HttpJwtSecurity();
    }

    private HttpJwtSecurity() {}


    public class AuthorizeExchangeBuilder extends AbstractServerWebExchangeMatcherRegistry<AuthorizeExchangeBuilder.Access> {
        private DelegatingReactiveAuthorizationManager.Builder managerBldr = DelegatingReactiveAuthorizationManager.builder();
        private ServerWebExchangeMatcher matcher;
        private boolean anyExchangeRegistered;

        public HttpJwtSecurity and() {
            return HttpJwtSecurity.this;
        }

        @Override
        public Access anyExchange() {
            Access result = super.anyExchange();
            anyExchangeRegistered = true;
            return result;
        }

        @Override
        protected Access registerMatcher(ServerWebExchangeMatcher matcher) {
            if(anyExchangeRegistered) {
                throw new IllegalStateException("Cannot register " + matcher + " which would be unreachable because anyExchange() has already been registered.");
            }
            if(this.matcher != null) {
                throw new IllegalStateException("The matcher " + matcher + " does not have an access rule defined");
            }
            this.matcher = matcher;
            return new Access();
        }

        protected WebFilter build() {
            if(this.matcher != null) {
                throw new IllegalStateException("The matcher " + matcher + " does not have an access rule defined");
            }
            return new AuthorizationWebFilter(managerBldr.build());
        }

        public final class Access {

            public AuthorizeExchangeBuilder permitAll() {
                return access( (a,e) -> Mono.just(new AuthorizationDecision(true)));
            }

            public AuthorizeExchangeBuilder denyAll() {
                return access( (a,e) -> Mono.just(new AuthorizationDecision(false)));
            }

            public AuthorizeExchangeBuilder hasRole(String role) {
                return access(AuthorityAuthorizationManager.hasRole(role));
            }

            public AuthorizeExchangeBuilder hasAuthority(String authority) {
                return access(AuthorityAuthorizationManager.hasAuthority(authority));
            }

            public AuthorizeExchangeBuilder authenticated() {
                return access(AuthenticatedAuthorizationManager.authenticated());
            }

            public AuthorizeExchangeBuilder access(ReactiveAuthorizationManager<AuthorizationContext> manager) {
                managerBldr.add(new ServerWebExchangeMatcherEntry<>(matcher, manager));
                matcher = null;
                return AuthorizeExchangeBuilder.this;
            }
        }
    }

}
