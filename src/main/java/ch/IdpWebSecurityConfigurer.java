package ch;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Configuration
public class IdpWebSecurityConfigurer extends WebSecurityConfigurerAdapter {

    @Value("#{systemProperties['users']}")
    private String users;

    @Autowired
    private AccessDeniedHandler accessDeniedHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
            .csrf()
            .disable()
            .authorizeRequests()
            .antMatchers("/get/**").hasAnyRole("USER")
            .anyRequest()
            .authenticated()
            .and()
            .formLogin()
            .loginPage("/login")
            .permitAll()
            .and()
            .logout()
            .permitAll()
            .and()
            .exceptionHandling().accessDeniedHandler(accessDeniedHandler);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        if (users != null) {
            String[] usersArray = users.split(",");
            for (String user : usersArray) {
                auth
                    .inMemoryAuthentication()
                    .withUser(user)
                    .password("{noop}paZZw0rd") // noop for plaintext
                    .roles("USER");
                System.out.println("User added: " + user);
            }
        }
    }

    @Component
    public class MyAccessDeniedHandler implements AccessDeniedHandler {

        @Override
        public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException {
            httpServletResponse.sendRedirect(httpServletRequest.getContextPath() + "/403");
        }

    }

}
