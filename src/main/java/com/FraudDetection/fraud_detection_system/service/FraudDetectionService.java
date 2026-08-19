package com.FraudDetection.fraud_detection_system.service;

import com.FraudDetection.fraud_detection_system.model.Transaction;
import com.FraudDetection.fraud_detection_system.repository.TransactionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class FraudDetectionService {

    @Autowired
    private TransactionRepository transactionRepository;

    public Transaction checkTransaction(Transaction transaction) {
        int riskScore = 0;
        List<String> reasons = new ArrayList<>();

        String account = transaction.getAccountNumber();
        double amount = transaction.getAmount() != null ? transaction.getAmount() : 0;
        String type = transaction.getTransactionType() != null ? transaction.getTransactionType().toUpperCase() : "";
        String location = transaction.getLocation() != null ? transaction.getLocation().toLowerCase() : "";

        // =========================
        // 1. VELOCITY / FREQUENCY
        // =========================
        LocalDateTime tenMinutesAgo = LocalDateTime.now().minusMinutes(10);
        List<Transaction> recent10min = transactionRepository
                .findByAccountNumberAndTimestampAfter(account, tenMinutesAgo);

        int recentCount = recent10min.size();

        if (recentCount >= 4) {
            riskScore += 50;
            reasons.add("High velocity: " + (recentCount + 1) + " transactions in 10 minutes");
        } else if (recentCount >= 3) {
            riskScore += 40;
            reasons.add("Velocity alert: " + (recentCount + 1) + " transactions in 10 minutes");
        } else if (recentCount >= 2) {
            riskScore += 25;
            reasons.add("Multiple transactions in short time");
        }

        // Also check last 1 hour
        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
        List<Transaction> recent1hour = transactionRepository
                .findByAccountNumberAndTimestampAfter(account, oneHourAgo);

        if (recent1hour.size() >= 6) {
            riskScore += 30;
            reasons.add("Unusual frequency: many transactions within 1 hour");
        }

        // =========================
        // 2. AMOUNT-BASED RULES
        // =========================
        if (amount >= 20000) {
            riskScore += 50;
            reasons.add("Very high transaction amount (RM " + amount + ")");
        } else if (amount >= 10000) {
            riskScore += 40;
            reasons.add("High transaction amount (RM " + amount + ")");
        } else if (amount >= 5000) {
            riskScore += 20;
            reasons.add("Moderately high amount (RM " + amount + ")");
        }

        // Round number amounts (common in fraud)
        if (amount > 1000 && amount % 1000 == 0) {
            riskScore += 10;
            reasons.add("Round amount detected (possible structuring)");
        }

        // Amount just below common limits
        if (amount >= 9900 && amount < 10000) {
            riskScore += 15;
            reasons.add("Amount just below RM 10,000 threshold");
        }

        // Very small repeated amounts (smurfing style)
        if (amount > 0 && amount <= 200 && recentCount >= 2) {
            riskScore += 20;
            reasons.add("Multiple small-value transactions detected");
        }

        // =========================
        // 3. TRANSACTION TYPE RULES
        // =========================
        if ("TRANSFER".equals(type) && amount >= 8000) {
            riskScore += 20;
            reasons.add("High-value TRANSFER detected");
        }

        if ("WITHDRAWAL".equals(type) && amount >= 5000) {
            riskScore += 15;
            reasons.add("High-value WITHDRAWAL detected");
        }

        // =========================
        // 4. LOCATION RULES
        // =========================
        if (location.contains("overseas") || location.contains("foreign") ||
            location.contains("unknown") || location.contains("russia") ||
            location.contains("nigeria") || location.contains("offshore")) {
            riskScore += 30;
            reasons.add("Suspicious / high-risk location: " + transaction.getLocation());
        }

        // =========================
        // 5. TIME-BASED RULES
        // =========================
        LocalTime time = LocalDateTime.now().toLocalTime();
        if (time.isAfter(LocalTime.MIDNIGHT) && time.isBefore(LocalTime.of(5, 0))) {
            riskScore += 25;
            reasons.add("Transaction during unusual hours (" + time.withNano(0) + ")");
        }

        // =========================
        // 6. STATISTICAL ANALYSIS
        // =========================
        List<Transaction> accountHistory = transactionRepository.findByAccountNumber(account);

        if (accountHistory.size() >= 3) {
            // Calculate average amount
            double sum = 0;
            for (Transaction t : accountHistory) {
                if (t.getAmount() != null) {
                    sum += t.getAmount();
                }
            }
            double average = sum / accountHistory.size();

            // Simple deviation (Z-score style)
            if (average > 0) {
                double deviationRatio = amount / average;

                if (deviationRatio >= 5) {
                    riskScore += 45;
                    reasons.add("Statistical anomaly: amount is " + String.format("%.1f", deviationRatio) + "x higher than account average");
                } else if (deviationRatio >= 3) {
                    riskScore += 30;
                    reasons.add("Amount significantly higher than account average (Avg: RM " + String.format("%.2f", average) + ")");
                } else if (deviationRatio >= 2) {
                    riskScore += 15;
                    reasons.add("Amount above normal spending pattern");
                }
            }
        } else if (accountHistory.isEmpty() && amount >= 5000) {
            // First / new account high amount
            riskScore += 20;
            reasons.add("High amount on account with little/no history");
        }

        // =========================
        // 7. COMBINED RISK PATTERNS
        // =========================
        if (amount >= 5000 && (location.contains("overseas") || location.contains("unknown"))) {
            riskScore += 15;
            reasons.add("High amount + suspicious location combination");
        }

        if (recentCount >= 2 && amount >= 3000) {
            riskScore += 15;
            reasons.add("Repeated transactions with significant amount");
        }

        // Cap score
        if (riskScore > 100) {
            riskScore = 100;
        }

        // Final status
        String status;
        if (riskScore >= 70) {
            status = "SUSPICIOUS";
        } else if (riskScore >= 40) {
            status = "SUSPICIOUS"; // still treat medium-high as suspicious for safety
        } else {
            status = "NORMAL";
        }

        // Slightly stricter threshold
        if (riskScore >= 50) {
            status = "SUSPICIOUS";
        } else {
            status = "NORMAL";
        }

        transaction.setRiskScore(riskScore);
        transaction.setStatus(status);
        transaction.setTimestamp(LocalDateTime.now());
        transaction.setReasons(reasons);

        return transactionRepository.save(transaction);
    }

    public List<Transaction> getAllTransactions() {
        return transactionRepository.findAll();
    }

    public Transaction generateRandomTransaction() {
        String[] accountNumbers = {"1001", "1002", "1003", "1004", "1005", "2001", "2002", "3001"};
        String[] types = {"TRANSFER", "WITHDRAWAL", "PAYMENT"};
        String[] locations = {
            "Kuala Lumpur", "Penang", "Johor Bahru", "Ipoh", "Melaka",
            "Overseas", "Unknown", "Foreign", "Shah Alam"
        };

        String account = accountNumbers[(int) (Math.random() * accountNumbers.length)];
        double amount = Math.round((Math.random() * 18000 + 30) * 100.0) / 100.0;
        String type = types[(int) (Math.random() * types.length)];
        String location = locations[(int) (Math.random() * locations.length)];

        Transaction transaction = new Transaction();
        transaction.setAccountNumber(account);
        transaction.setAmount(amount);
        transaction.setTransactionType(type);
        transaction.setLocation(location);

        return checkTransaction(transaction);
    }

    public Transaction saveTransaction(Transaction transaction) {
        return transactionRepository.save(transaction);
    }
}