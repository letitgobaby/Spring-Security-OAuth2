package com.example.letitgobaby.app.clients;

import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.letitgobaby.model.ClientInfo;
import com.example.letitgobaby.model.ClientInfoRepository;

import ch.qos.logback.core.net.server.Client;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ClientInfoService {
  
  private final ClientInfoRepository clientRepository;
  private final PasswordEncoder encoder;

  @Transactional
  public ClientInfo enrollClientInfo(String clientId, String clientSecret) {
    Optional<ClientInfo> client = this.clientRepository.findByClientId(clientId);
    if (client.isPresent()) {
      return null;
    }

    ClientInfo entity = ClientInfo.builder()
      .clientId(clientId)
      .clientSecret(this.encoder.encode(clientSecret))
      .build();
    
    return this.clientRepository.save(entity);
  }

}
