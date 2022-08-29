package com.example.letitgobaby.security.token.sub;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class CodeGrantToken extends AbstractAuthenticationToken {

  private String responseType;
  private String clientId;
  private String redirectUri;
        // response_type=code
        // client_id=dple3JolZrc9R877kmADdK9J
        // redirect_uri=https://www.oauth.com/playground/authorization-code.html
  public CodeGrantToken(Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
  }

  @Override
  public Object getCredentials() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Object getPrincipal() {
    // TODO Auto-generated method stub
    return null;
  }
  
}
