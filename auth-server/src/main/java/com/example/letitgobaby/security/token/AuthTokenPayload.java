package com.example.letitgobaby.security.token;

import java.util.Collection;

public class AuthTokenPayload extends AbstractAuthenticationToken {

  private String accessToken;
  private String refreshToken;

  public AuthTokenPayload(String aToken, String rToken) {
    super(null);
    this.accessToken = aToken;
    this.refreshToken = rToken;
  }

  public AuthTokenPayload(Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
  }

  public String getAccessToken() {
    return this.accessToken;
  }

  public String getRefreshToken() {
    return this.refreshToken;
  }

  @Override
  public Object getCredentials() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public String getPrincipal() {
    return null;
  }
}
