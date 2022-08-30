package com.example.letitgobaby.model;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SubLoginRepository extends JpaRepository<SubLogin, Long> {
  
  Optional<SubLogin> findByClientId(String clientId);

  Optional<SubLogin> findByClientIdAndCode(String clientId, String code);

}
