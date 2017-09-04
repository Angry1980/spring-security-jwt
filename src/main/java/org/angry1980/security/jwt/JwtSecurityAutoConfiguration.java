package org.angry1980.security.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.config.web.server.HttpJwtSecurity;
import org.springframework.security.web.server.context.ServerWebExchangeAttributeSecurityContextRepositoryFix;

import static org.springframework.security.config.web.server.HttpJwtSecurity.jwt;

/**
 * Auto-configuration for JSON Web Token authentication method.
 */
@Configuration
@ConditionalOnProperty(name = "security.jwt.signingKey", matchIfMissing = false)
public class JwtSecurityAutoConfiguration {

    @Value("security.jwt.signingKey")
    private String signingKey;

    /**
     * Prototype bean of Jwt Security builder which later can be used to create web filter chains.
     */
    @Bean
    @Scope("prototype")
    public HttpJwtSecurity jwtSecurity() {
        HttpJwtSecurity security = jwt();
        security.signingKey(signingKey);
        //todo: delete after spring fix
        security.securityContextRepository(new ServerWebExchangeAttributeSecurityContextRepositoryFix());
        //security.securityContextRepository(new ServerWebExchangeAttributeSecurityContextRepository());
        return security;
    }


}
