package com.example.letitgobaby.security.token.sub;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class AuhorizeToken extends AbstractAuthenticationToken {

  private String resType;
  private String clientId;
  private String redirectUri;
  private String code;

  public AuhorizeToken(String resType, String clientId, String redirectUri) {
    super(null);
    this.resType = resType;
    this.clientId = clientId;
    this.redirectUri = redirectUri;
  }

  public AuhorizeToken(Collection<? extends GrantedAuthority> authorities) {
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
  
  public String getResType() {
    return this.resType;
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

  public void authenticated() {
    super.setAuthenticated(true);
  }
  
}
