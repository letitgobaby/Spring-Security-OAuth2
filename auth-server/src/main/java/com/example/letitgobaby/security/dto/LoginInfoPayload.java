package com.example.letitgobaby.security.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter @Setter @ToString
public class LoginInfoPayload {
  private String userId;
  private String pswd;
}
