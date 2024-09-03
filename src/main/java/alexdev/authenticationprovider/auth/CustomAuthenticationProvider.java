package alexdev.authenticationprovider.auth;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService service;
    private final PasswordEncoder encoder;

    public CustomAuthenticationProvider(UserDetailsService service, PasswordEncoder encoder) {
        this.service = service;
        this.encoder = encoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var username = authentication.getName();
        var password = authentication.getCredentials().toString();
        var userDetails = service.loadUserByUsername(username);
        if (!encoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("something went wrong");
        }
        return new UsernamePasswordAuthenticationToken(
                username,
                password,
                userDetails.getAuthorities()
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
