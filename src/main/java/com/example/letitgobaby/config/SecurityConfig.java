package com.example.letitgobaby.config;

import java.util.List;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.example.letitgobaby.security.filter.A_LoginFilter;
import com.example.letitgobaby.security.filter.B_LoginFilter;

import lombok.RequiredArgsConstructor;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final String[] PERMIT_URL = new String[] { "/login" };

  private ProviderManager providerManagerByLogin;
  private List<AuthenticationProvider> providerListByLogin;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    setupProviders();

    http.httpBasic().disable();
    http.cors();
    http.csrf().disable();

    http
      .sessionManagement(sseion -> sseion.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .requestMatchers(matchers -> matchers.antMatchers("/static/**"))
      .authorizeHttpRequests(authorize -> {
        authorize
          .antMatchers(PERMIT_URL).permitAll()
          .anyRequest().authenticated();
      })
      .exceptionHandling()
      .authenticationEntryPoint((req, res, ex) -> {
        res.sendError(HttpServletResponse.SC_FORBIDDEN, ex.getMessage());
      })
      .accessDeniedHandler((req, res, ex) -> {
        res.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
      });

    http
      .addFilterBefore(a_LoginFilter(), UsernamePasswordAuthenticationFilter.class)
      .addFilterBefore(b_LoginFilter(), UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  private Filter a_LoginFilter() {
    String LOGIN_URL = "/a/login";
    RequestMatcher login_requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.GET.name());
    A_LoginFilter loginFilter = new A_LoginFilter(login_requestMatcher);
    loginFilter.setAuthenticationManager(getAuthManagerForLogin());
    return loginFilter;
  }

  private Filter b_LoginFilter() {
    String LOGIN_URL = "/b/login";
    RequestMatcher login_requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.POST.name());
    B_LoginFilter loginFilter = new B_LoginFilter(login_requestMatcher);
    loginFilter.setAuthenticationManager(getAuthManagerForLogin());
    return loginFilter;
  }

  private AuthenticationManager getAuthManagerForLogin() {
    if (this.providerManagerByLogin == null) {
      this.providerManagerByLogin = new ProviderManager(this.providerListByLogin);
    }
    return this.providerManagerByLogin;
  }

  private void setupProviders() {

  }

  @Bean
  public CorsFilter corsFilter() {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowCredentials(true);
    config.addAllowedOrigin("*");
    config.addAllowedHeader("*");
    config.addAllowedMethod("*");
    source.registerCorsConfiguration("/**", config);
    return new CorsFilter(source);
  }

  @Bean
  public PasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }

}
