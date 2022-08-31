package com.example.letitgobaby.security.token.sub;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class SubAutoLoginToken extends AbstractAuthenticationToken {

  private String clientId;
  private String redirectUri;
  private String rToken;
  private String code;

  public SubAutoLoginToken(String clientId, String redirectUri, String rToken) {
    super(null);
    super.setAuthenticated(false);
    this.clientId = clientId;
    this.redirectUri = redirectUri;
    this.rToken = rToken;
  }

  public SubAutoLoginToken(Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
  }

  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public String getPrincipal() {
    return this.clientId;
  }
  
  public String getToken() {
    return this.rToken;
  }

  public String getRedirectUri() {
    return this.redirectUri;
  }

  public String getCode() {
    return this.code;
  }

  public void setCode(String code) {
    this.code = code;
  }

  public SubAutoLoginToken authenticated() {
    super.setAuthenticated(true);
    return this;
  }

}
