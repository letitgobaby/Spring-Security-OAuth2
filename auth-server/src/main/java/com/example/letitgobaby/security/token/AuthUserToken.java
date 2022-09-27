package com.example.letitgobaby.security.token;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class AuthUserToken extends AbstractAuthenticationToken {

  private String userId;
  private String pswd;

  private String accessToken;
  private String refreshToken;

  public AuthUserToken(String userId, String pswd) {
    super(null);
    super.setAuthenticated(false);
    this.userId = userId;
    this.pswd = pswd;
  }

  public AuthUserToken(String userId, Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    super.setAuthenticated(true);
    this.userId = userId;
  }

  @Override
  public String getPrincipal() {
    return this.userId;
  }

  @Override
  public String getCredentials() {
    return this.pswd;
  }

  public void setToken(String aToken, String rToken) {
    this.accessToken = aToken;
    this.refreshToken = rToken;
  }

  public String getAccessToken() {
    return this.accessToken;
  }

  public String getRefreshToken() {
    return this.refreshToken;
  }

}
