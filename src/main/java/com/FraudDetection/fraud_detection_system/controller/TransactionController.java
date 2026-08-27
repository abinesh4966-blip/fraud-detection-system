package com.FraudDetection.fraud_detection_system.controller;

import com.FraudDetection.fraud_detection_system.model.Transaction;
import com.FraudDetection.fraud_detection_system.service.FraudDetectionService;
import com.FraudDetection.fraud_detection_system.service.IsolationForestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/transactions")
@CrossOrigin(origins = "*")
public class TransactionController {

    @Autowired
    private FraudDetectionService fraudDetectionService;

    @Autowired
    private IsolationForestService isolationForestService;

    @PostMapping("/check")
    public Transaction checkTransaction(@RequestBody Transaction transaction) {
        return fraudDetectionService.checkTransaction(transaction);
    }

    /** Admin: all transactions */
    @GetMapping("/history")
    public List<Transaction> getHistory() {
        return fraudDetectionService.getAllTransactions();
    }

    /** User: only one account (backend filter) */
    @GetMapping("/my-history")
    public List<Transaction> getMyHistory(@RequestParam String accountNumber) {
        if (accountNumber == null || accountNumber.isBlank()) {
            return List.of();
        }
        return fraudDetectionService.getAllTransactions().stream()
                .filter(t -> t != null && accountNumber.equals(String.valueOf(t.getAccountNumber())))
                .collect(Collectors.toList());
    }

    @GetMapping("/stats")
    public Map<String, Object> getStats() {
        List<Transaction> all = fraudDetectionService.getAllTransactions();
        long total = all.size();
        long normal = 0, suspicious = 0, falsePositive = 0;
        for (Transaction t : all) {
            if (t == null) continue;
            if (t.isFalsePositive()) falsePositive++;
            else if ("NORMAL".equals(t.getStatus())) normal++;
            else if ("SUSPICIOUS".equals(t.getStatus())) suspicious++;
        }
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
    public Map<String, Object> uploadCsv(@RequestParam("file") MultipartFile file) {
        Map<String, Object> response = new HashMap<>();
        int successCount = 0, errorCount = 0;
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()));
            String line;
            boolean firstLine = true;
            while ((line = reader.readLine()) != null) {
                if (firstLine) { firstLine = false; continue; }
                if (line.trim().isEmpty()) continue;
                try {
                    String[] parts = line.split(",");
                    if (parts.length >= 4) {
                        Transaction tx = new Transaction();
                        tx.setAccountNumber(parts[0].trim());
                        tx.setAmount(Double.parseDouble(parts[1].trim()));
                        tx.setTransactionType(parts[2].trim());
                        tx.setLocation(parts[3].trim());
                        fraudDetectionService.checkTransaction(tx);
                        successCount++;
                    } else errorCount++;
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
            Transaction tx = null;
            for (Transaction t : fraudDetectionService.getAllTransactions()) {
                if (t != null && t.getId() != null && t.getId().equals(id)) {
                    tx = t;
                    break;
                }
            }
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

    @DeleteMapping("/clear-all")
    public Map<String, Object> clearAll() {
        Map<String, Object> res = new HashMap<>();
        long deleted = fraudDetectionService.clearAllTransactions();
        res.put("success", true);
        res.put("deleted", deleted);
        res.put("message", "All transactions cleared and ML model reset");
        return res;
    }

    @DeleteMapping("/clear-mine")
    public Map<String, Object> clearMine(@RequestParam String accountNumber) {
        Map<String, Object> res = new HashMap<>();
        long deleted = fraudDetectionService.clearAccountTransactions(accountNumber);
        res.put("success", true);
        res.put("deleted", deleted);
        res.put("message", "Cleared " + deleted + " transactions for account " + accountNumber);
        return res;
    }

    @PostMapping("/ml/reset")
    public Map<String, Object> resetMl() {
        isolationForestService.reset();
        Map<String, Object> res = new HashMap<>();
        res.put("success", true);
        res.put("ready", false);
        res.put("trainSize", 0);
        res.put("message", "ML model cleared. Rules-only scoring until you retrain.");
        return res;
    }

    @PostMapping("/ml/retrain")
    public Map<String, Object> retrainMl() {
        Map<String, Object> res = new HashMap<>();
        boolean ok = isolationForestService.retrain();
        res.put("success", ok);
        res.put("ready", isolationForestService.isReady());
        res.put("trainSize", isolationForestService.getTrainSize());
        res.put("lastTrained", isolationForestService.getLastTrained() != null
                ? isolationForestService.getLastTrained().toString() : null);
        res.put("message", ok ? "Isolation Forest retrained" : "Not enough NORMAL data (need ~12+)");
        return res;
    }

    @GetMapping("/ml/status")
    public Map<String, Object> mlStatus() {
        Map<String, Object> res = new HashMap<>();
        res.put("ready", isolationForestService.isReady());
        res.put("trainSize", isolationForestService.getTrainSize());
        res.put("lastTrained", isolationForestService.getLastTrained() != null
                ? isolationForestService.getLastTrained().toString() : null);
        return res;
    }
}