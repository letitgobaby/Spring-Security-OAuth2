package com.example.letitgobaby.security.token.sub;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.example.letitgobaby.security.dto.SubAuthGrantPayload;

public class AuthGrantToken extends AbstractAuthenticationToken {

  private String clientId;
  private String clientSecret;
  private String grantType;
  private String redirectUri;
  private String code;

  private String accessToken;
  private String refreshToken;

  public AuthGrantToken(SubAuthGrantPayload paylod) {
    super(null);
    this.clientId = paylod.getClient_id();
    this.clientSecret = paylod.getClient_secret();
    this.grantType = paylod.getGrant_type();
    this.redirectUri = paylod.getRedirect_uri();
    this.code = paylod.getCode();
  }


  public AuthGrantToken(String clientId, String clientSecret, String grantType, String redirectUri, String code) {
    super(null);
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.grantType = grantType;
    this.redirectUri = redirectUri;
    this.code = code;
  }

  public AuthGrantToken(Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
  }

  @Override
  public String getCredentials() {
    return this.clientSecret;
  }

  @Override
  public String getPrincipal() {
    return this.clientId;
  }
  
  public String getGrantType() {
    return this.grantType;
  }

  public String getRedirectUri() {
    return this.redirectUri;
  }

  public String getCode() {
    return this.code;
  }

  public String getAccessToken() {
    return this.accessToken;
  }

  public String getRefreshToken() {
    return this.refreshToken;
  }

  public void setAccessRefreshToken(String aToken, String rToken) {
    super.setAuthenticated(true);
    this.accessToken = aToken;
    this.refreshToken = rToken;
  }

}
