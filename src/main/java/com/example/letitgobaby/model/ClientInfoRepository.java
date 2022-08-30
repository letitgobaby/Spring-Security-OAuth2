package com.example.letitgobaby.model;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientInfoRepository extends JpaRepository<ClientInfo, String> {
  
  Optional<ClientInfo> findByClientId(String clientId);

}
