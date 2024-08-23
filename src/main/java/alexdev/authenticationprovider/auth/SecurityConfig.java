package alexdev.authenticationprovider.auth;

import alexdev.authenticationprovider.user.Users;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    DefaultUserDetailsService defaultUserDetailsService(Users repository) {
        return new DefaultUserDetailsService(repository);
    }

    @Bean
    CustomAuthenticationProvider customAuthenticationProvider(DefaultUserDetailsService service, PasswordEncoder encoder) {
        return new CustomAuthenticationProvider(service, encoder);
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, CustomAuthenticationProvider customAuthenticationProvider) throws Exception {

        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(Customizer.withDefaults())
                .authenticationProvider(customAuthenticationProvider)
                .authorizeHttpRequests(
                        c -> c
                                .requestMatchers("/health").permitAll()
                                .requestMatchers(HttpMethod.GET, "/user").hasAnyRole("ADMIN", "USER")
                                .requestMatchers(HttpMethod.POST, "/user").hasRole("ADMIN")
                                .anyRequest().authenticated())
                .build();
    }

    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return web -> {
            web.ignoring().requestMatchers("/h2-console/**");
        };
    }

}
