package com.example.letitgobaby.security.provider;

import java.util.Optional;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.auth0.jwt.interfaces.Claim;
import com.example.letitgobaby.model.User;
import com.example.letitgobaby.model.UserRepository;
import com.example.letitgobaby.security.dto.UserInfo;
import com.example.letitgobaby.security.token.JwtToken;
import com.example.letitgobaby.utils.JWTBuilder;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtVerifyProvider implements AuthenticationProvider {
  
  private final UserRepository userRepository;
  private final JWTBuilder jwtBuilder;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String token = (String) authentication.getPrincipal();
    Claim cliam = this.jwtBuilder.getClaim(token, "userInfo");
    UserInfo userInfo = cliam.as(UserInfo.class);

    Optional<User> user = this.userRepository.findByUserId(userInfo.getUserId());
    if (!user.isPresent()) {
      return null;
    }

    
    return null;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return JwtToken.class.isAssignableFrom(authentication);
  }

}
