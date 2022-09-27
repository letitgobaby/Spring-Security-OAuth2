package com.example.letitgobaby.web.apis.payload;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter @Setter @ToString
public class SignUpPayload {
  
  private String userId;
  private String password;

}
