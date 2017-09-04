package org.angry1980.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Create list of roles based on info contained in json web token
 */
public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Jws<Claims> token = (Jws<Claims>) authentication.getCredentials();
        List<String> scopes = (List<String>)token.getBody().get("scopes");
        List<GrantedAuthority> authorities = scopes.stream()
                .map(scope -> "ROLE_" + scope)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        User user = new User(token.getBody().getSubject(), "", authorities);
        return new JwtAuthenticationToken(token, user, authorities);
    }

    @Override
    public boolean supports(Class<?> _class) {
        return JwtAuthenticationToken.class.isAssignableFrom(_class);
    }
}
