package com.FraudDetection.fraud_detection_system.controller;

import com.FraudDetection.fraud_detection_system.model.Transaction;
import com.FraudDetection.fraud_detection_system.service.FraudDetectionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/transactions")
public class TransactionController {

    @Autowired
    private FraudDetectionService fraudDetectionService;

    @PostMapping("/check")
    public Transaction checkTransaction(@RequestBody Transaction transaction) {
        return fraudDetectionService.checkTransaction(transaction);
    }

    @GetMapping("/history")
    public List<Transaction> getHistory() {
        return fraudDetectionService.getAllTransactions();
    }

    @GetMapping("/stats")
    public Map<String, Object> getStats() {
    List<Transaction> all = fraudDetectionService.getAllTransactions();

    long total = all.size();
    long normal = all.stream()
            .filter(t -> "NORMAL".equals(t.getStatus()) && !t.isFalsePositive())
            .count();
    long suspicious = all.stream()
            .filter(t -> "SUSPICIOUS".equals(t.getStatus()) && !t.isFalsePositive())
            .count();
    long falsePositive = all.stream()
            .filter(t -> t.isFalsePositive())
            .count();

    Map<String, Object> stats = new HashMap<>();
    stats.put("total", total);
    stats.put("normal", normal);
    stats.put("suspicious", suspicious);
    stats.put("falsePositive", falsePositive);

    return stats;
}

    @PostMapping("/generate")
    public Transaction generateTransaction() {
        return fraudDetectionService.generateRandomTransaction();
    }

    @PostMapping("/upload")
    public Map<String, Object> uploadCSV(@RequestParam("file") MultipartFile file) {
        Map<String, Object> response = new HashMap<>();
        int successCount = 0;
        int errorCount = 0;

        try {
            if (file.isEmpty()) {
                response.put("success", false);
                response.put("message", "File is empty");
                return response;
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()));
            String line;
            boolean isFirstLine = true;

            while ((line = reader.readLine()) != null) {
                if (isFirstLine) {
                    isFirstLine = false;
                    continue;
                }

                try {
                    String[] data = line.split(",");
                    if (data.length >= 4) {
                        Transaction transaction = new Transaction();
                        transaction.setAccountNumber(data[0].trim());
                        transaction.setAmount(Double.parseDouble(data[1].trim()));
                        transaction.setTransactionType(data[2].trim());
                        transaction.setLocation(data[3].trim());

                        fraudDetectionService.checkTransaction(transaction);
                        successCount++;
                    }
                } catch (Exception e) {
                    errorCount++;
                }
            }

            reader.close();

            response.put("success", true);
            response.put("message", "Upload completed");
            response.put("processed", successCount);
            response.put("failed", errorCount);

        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "Error reading file: " + e.getMessage());
        }

        return response;
    }

    @PutMapping("/{id}/false-positive")
    public Map<String, Object> markAsFalsePositive(@PathVariable Long id) {
        Map<String, Object> response = new HashMap<>();
        try {
            Transaction tx = fraudDetectionService.getAllTransactions().stream()
                    .filter(t -> t.getId().equals(id))
                    .findFirst()
                    .orElse(null);

            if (tx == null) {
                response.put("success", false);
                response.put("message", "Transaction not found");
                return response;
            }

            tx.setFalsePositive(true);
            fraudDetectionService.saveTransaction(tx);

            response.put("success", true);
            response.put("message", "Marked as False Positive");
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", e.getMessage());
        }
        return response;
    }
}