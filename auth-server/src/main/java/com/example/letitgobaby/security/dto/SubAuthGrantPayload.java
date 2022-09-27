package com.example.letitgobaby.security.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter @Setter @ToString
public class SubAuthGrantPayload {
  private String grant_type;
  private String client_id;
  private String client_secret;
  private String redirect_uri;
  private String code;
}
