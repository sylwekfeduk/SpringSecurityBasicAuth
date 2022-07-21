package pl.fis.lbd.springsecurity.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/admin").hasAuthority("ADMIN")
                .antMatchers(HttpMethod.PUT,"/api/user").hasAnyAuthority("USER_EDIT", "ADMIN")
                .antMatchers(HttpMethod.GET,"/api/user").hasAnyAuthority("USER_READ", "ADMIN")
                .anyRequest().authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails admin = User.builder()
                .password(passwordEncoder().encode("admin"))
                .username("admin")
                .authorities("ADMIN")
                .build();
        UserDetails user = User.builder()
                .password(passwordEncoder().encode("user"))
                .username("user")
                .authorities("USER_READ", "USER_EDIT")
                .build();
        UserDetails spectator = User.builder()
                .password(passwordEncoder().encode("spectator"))
                .username("spectator")
                .authorities("USER_READ")
                .build();
        return new InMemoryUserDetailsManager(admin, user, spectator);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }
}
