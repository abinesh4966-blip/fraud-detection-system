package com.FraudDetection.fraud_detection_system.repository;

import com.FraudDetection.fraud_detection_system.model.Transaction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface TransactionRepository extends JpaRepository<Transaction, Long> {

    List<Transaction> findByAccountNumberAndTimestampAfter(String accountNumber, LocalDateTime timestamp);

    List<Transaction> findByAccountNumber(String accountNumber);
}