package org.angry1980.security.jwt

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Scope
import org.springframework.security.config.web.server.HttpJwtSecurity
import org.springframework.security.web.server.context.ServerWebExchangeAttributeSecurityContextRepositoryFix

/**
 * Auto-configuration for JSON Web Token authentication method.
 */
@Configuration
@ConditionalOnProperty(name = arrayOf("security.jwt.signingKey"), matchIfMissing = false)
class JwtSecurityAutoConfiguration {

    @Value("security.jwt.signingKey")
    private lateinit var signingKey: String

    /**
     * Prototype bean of Jwt Security builder which later can be used to create web filter chains.
     */
    @Bean
    @Scope("prototype")
    fun jwtSecurity() = HttpJwtSecurity(signingKey)
            .apply {
                //todo: delete after spring fix
                securityContextRepository = ServerWebExchangeAttributeSecurityContextRepositoryFix()
                //securityContextRepository =  ServerWebExchangeAttributeSecurityContextRepository()
            }

}
