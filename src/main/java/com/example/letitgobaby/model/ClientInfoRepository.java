package com.example.letitgobaby.model;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientInfoRepository extends JpaRepository<ClientInfo, Long> {
  
  Optional<ClientInfo> findByClientId(String clientId);

}
