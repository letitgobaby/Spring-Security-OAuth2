package com.example.letitgobaby.security.token.sub;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class ConsentToken extends AbstractAuthenticationToken {

  private String scope;
  private String clientId;
  private String redirectUri;
  private String code;
  private String userInfo;

  public ConsentToken(String scope, String clientId, String redirectUri, String userInfo) {
    super(null);
    this.scope = scope;
    this.clientId = clientId;
    this.redirectUri = redirectUri;
    this.userInfo = userInfo;
  }

  public ConsentToken(Collection<? extends GrantedAuthority> authorities) {
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

  public String getScope() {
    return this.scope;
  }
  
  public String getRedirectUri() {
    return this.redirectUri;
  }

  public String getCode() {
    return this.code;
  }

  public String getUserInfoToken() {
    return this.userInfo;
  }

  public void setCode(String code) {
    super.setAuthenticated(true);
    this.code = code;
  }

  public void authenticated() {
    super.setAuthenticated(true);
  }

}
