package com.FraudDetection.fraud_detection_system.service;

import com.FraudDetection.fraud_detection_system.model.Transaction;
import com.FraudDetection.fraud_detection_system.repository.TransactionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class FraudDetectionService {

    @Autowired
    private TransactionRepository transactionRepository;

    @Autowired
    private IsolationForestService isolationForestService;

    public Transaction checkTransaction(Transaction transaction) {
        int velocityScore = 0;
        int amountScore = 0;
        int locationScore = 0;
        int timeScore = 0;
        int patternScore = 0;
        int spendScore = 0;
        int mlScore = 0;

        List<String> reasons = new ArrayList<>();

        String account = transaction.getAccountNumber() != null ? transaction.getAccountNumber().trim() : "";
        double amount = transaction.getAmount() != null ? transaction.getAmount() : 0;
        String type = transaction.getTransactionType() != null ? transaction.getTransactionType().toUpperCase().trim() : "";
        String location = transaction.getLocation() != null ? transaction.getLocation().toLowerCase().trim() : "";

        LocalDateTime now = LocalDateTime.now();
        LocalTime time = now.toLocalTime();
        DayOfWeek day = now.getDayOfWeek();
        LocalDate today = now.toLocalDate();

        List<Transaction> last10Min = transactionRepository
                .findByAccountNumberAndTimestampAfter(account, now.minusMinutes(10));
        List<Transaction> last1Hour = transactionRepository
                .findByAccountNumberAndTimestampAfter(account, now.minusHours(1));
        List<Transaction> last24Hours = transactionRepository
                .findByAccountNumberAndTimestampAfter(account, now.minusHours(24));
        List<Transaction> accountHistory = transactionRepository.findByAccountNumber(account);

        int count10 = last10Min.size();
        int count1h = last1Hour.size();
        int count24h = last24Hours.size();

        // 1. VELOCITY
        if (count10 >= 6) {
            velocityScore = 40;
            reasons.add("Extreme velocity: " + (count10 + 1) + " transactions in 10 minutes");
        } else if (count10 >= 4) {
            velocityScore = 28;
            reasons.add("High velocity: " + (count10 + 1) + " transactions in 10 minutes");
        } else if (count10 >= 3) {
            velocityScore = 16;
            reasons.add("Multiple transactions within 10 minutes");
        }
        if (count1h >= 12) {
            velocityScore = Math.min(45, velocityScore + 12);
            reasons.add("Unusual frequency: " + (count1h + 1) + " transactions in 1 hour");
        } else if (count1h >= 8) {
            velocityScore = Math.min(45, velocityScore + 8);
            reasons.add("Elevated transaction frequency in the last hour");
        }
        if (count24h >= 25) {
            velocityScore = Math.min(45, velocityScore + 8);
            reasons.add("Abnormally high daily activity (" + (count24h + 1) + " in 24h)");
        }
        velocityScore = Math.min(velocityScore, 45);

        // 2. AMOUNT
        if (amount >= 25000) {
            amountScore = 45;
            reasons.add("Extremely high amount (RM " + amount + ")");
        } else if (amount >= 15000) {
            amountScore = 35;
            reasons.add("Very high amount (RM " + amount + ")");
        } else if (amount >= 10000) {
            amountScore = 28;
            reasons.add("High amount (RM " + amount + ")");
        } else if (amount >= 5000) {
            amountScore = 14;
            reasons.add("Moderately high amount (RM " + amount + ")");
        }
        if (amount >= 1000 && amount % 1000 == 0) {
            amountScore += 8;
            reasons.add("Round amount detected (possible structuring)");
        }
        if (amount >= 9000 && amount < 10000) {
            amountScore += 12;
            reasons.add("Amount just below RM 10,000 threshold");
        }
        if (amount >= 4900 && amount < 5000) {
            amountScore += 8;
            reasons.add("Amount just below RM 5,000 threshold");
        }
        if (amount > 0 && amount <= 150 && count10 >= 3) {
            amountScore += 14;
            reasons.add("Burst of very small transactions detected");
        }
        // NEW: micro card-testing pattern
        if (amount > 0 && amount <= 50 && count1h >= 4) {
            amountScore = Math.min(50, amountScore + 16);
            reasons.add("Possible card-testing: many micro transactions in 1 hour");
        }
        // NEW: odd cents on high value (social engineering style)
        if (amount >= 3000) {
            double cents = amount - Math.floor(amount);
            if (cents > 0.01 && cents < 0.99 && (amount % 1 != 0)) {
                // mild signal only
            }
        }
        amountScore = Math.min(amountScore, 50);

        if ("TRANSFER".equals(type) && amount >= 10000) {
            amountScore = Math.min(50, amountScore + 10);
            reasons.add("High-value TRANSFER");
        } else if ("TRANSFER".equals(type) && amount >= 5000) {
            amountScore = Math.min(50, amountScore + 6);
            reasons.add("Medium-high TRANSFER amount");
        }
        if ("WITHDRAWAL".equals(type) && amount >= 5000) {
            amountScore = Math.min(50, amountScore + 8);
            reasons.add("High-value WITHDRAWAL");
        }

        // 3. LOCATION
        boolean suspiciousLocation =
                location.contains("overseas") || location.contains("foreign") ||
                location.contains("unknown") || location.contains("offshore") ||
                location.contains("russia") || location.contains("nigeria") ||
                location.contains("dark") || location.contains("vpn");

        if (suspiciousLocation) {
            locationScore = 25;
            reasons.add("Suspicious/high-risk location: " + transaction.getLocation());
        }
        if (count1h >= 2) {
            Set<String> locations = new HashSet<>();
            for (Transaction t : last1Hour) {
                if (t.getLocation() != null) locations.add(t.getLocation().toLowerCase().trim());
            }
            locations.add(location);
            if (locations.size() >= 3) {
                locationScore = Math.max(locationScore, 22);
                reasons.add("Location jumping detected across multiple places quickly");
            }
        }
        locationScore = Math.min(locationScore, 30);

        // 4. TIME
        if (time.isAfter(LocalTime.MIDNIGHT) && time.isBefore(LocalTime.of(5, 0))) {
            timeScore = 18;
            reasons.add("Transaction during high-risk hours (12AM - 5AM)");
        } else if (time.isAfter(LocalTime.of(23, 0)) || time.isBefore(LocalTime.of(6, 0))) {
            timeScore = 8;
            reasons.add("Transaction during uncommon hours");
        }
        if ((day == DayOfWeek.SATURDAY || day == DayOfWeek.SUNDAY) && amount >= 8000) {
            timeScore += 6;
            reasons.add("High-value weekend transaction");
        }
        // NEW: late night + transfer
        if ((time.isAfter(LocalTime.of(1, 0)) && time.isBefore(LocalTime.of(5, 0)))
                && "TRANSFER".equals(type) && amount >= 2000) {
            timeScore = Math.min(22, timeScore + 10);
            reasons.add("Late-night TRANSFER with significant amount");
        }
        timeScore = Math.min(timeScore, 22);

        // 5. PATTERNS / HISTORY
        if (accountHistory.size() >= 3) {
            double sum = 0;
            int valid = 0;
            for (Transaction t : accountHistory) {
                if (t.getAmount() != null) {
                    sum += t.getAmount();
                    valid++;
                }
            }
            if (valid > 0) {
                double average = sum / valid;
                if (average > 0) {
                    double ratio = amount / average;
                    if (ratio >= 8) {
                        patternScore = 30;
                        reasons.add("Severe statistical anomaly: " + String.format("%.1fx", ratio) + " above average");
                    } else if (ratio >= 4.5) {
                        patternScore = 20;
                        reasons.add("Strong deviation from account average (Avg RM " + String.format("%.2f", average) + ")");
                    } else if (ratio >= 3.0) {
                        patternScore = 10;
                        reasons.add("Amount above normal spending pattern");
                    }
                }
            }
        } else if (amount >= 10000) {
            patternScore = 12;
            reasons.add("High amount on low-history account");
        }

        // NEW: repeated same amount (possible automation)
        if (amount > 0 && last1Hour.size() >= 2) {
            int sameAmount = 0;
            for (Transaction t : last1Hour) {
                if (t.getAmount() != null && Math.abs(t.getAmount() - amount) < 0.01) sameAmount++;
            }
            if (sameAmount >= 2) {
                patternScore = Math.min(30, patternScore + 14);
                reasons.add("Repeated identical amount in a short period");
            }
        }

        // NEW: sudden type shift (mostly PAYMENT history, now large TRANSFER)
        if ("TRANSFER".equals(type) && amount >= 3000 && accountHistory.size() >= 4) {
            long paymentLike = accountHistory.stream()
                    .filter(t -> t.getTransactionType() != null
                            && "PAYMENT".equalsIgnoreCase(t.getTransactionType()))
                    .count();
            if (paymentLike >= accountHistory.size() * 0.7) {
                patternScore = Math.min(30, patternScore + 12);
                reasons.add("Sudden shift from PAYMENT pattern to large TRANSFER");
            }
        }

        // NEW: dormant-like account (no tx in history sample but huge amount) — low history already handled
        if (accountHistory.isEmpty() && amount >= 5000 && "TRANSFER".equals(type)) {
            patternScore = Math.min(30, patternScore + 14);
            reasons.add("First-seen account making large TRANSFER");
        }

        // NEW: high-risk combo night + overseas + transfer
        if (suspiciousLocation && "TRANSFER".equals(type)
                && time.isAfter(LocalTime.MIDNIGHT) && time.isBefore(LocalTime.of(6, 0))) {
            patternScore = Math.min(30, patternScore + 12);
            reasons.add("High-risk combo: night + overseas/unknown + TRANSFER");
        }

        patternScore = Math.min(patternScore, 30);

        // 6. SPEND WINDOWS
        double dailySpend = amount;
        double monthlySpend = amount;
        double yearlySpend = amount;
        for (Transaction t : accountHistory) {
            if (t.getAmount() == null || t.getTimestamp() == null) continue;
            LocalDate txDate = t.getTimestamp().toLocalDate();
            double txAmount = t.getAmount();
            if (txDate.equals(today)) dailySpend += txAmount;
            if (txDate.getYear() == today.getYear() && txDate.getMonth() == today.getMonth()) monthlySpend += txAmount;
            if (txDate.getYear() == today.getYear()) yearlySpend += txAmount;
        }
        if (dailySpend >= 30000) {
            spendScore = 22;
            reasons.add("Daily spending spike: RM " + String.format("%.2f", dailySpend));
        } else if (dailySpend >= 15000) {
            spendScore = 14;
            reasons.add("High daily spending: RM " + String.format("%.2f", dailySpend));
        } else if (dailySpend >= 8000) {
            spendScore = 8;
            reasons.add("Elevated daily spending: RM " + String.format("%.2f", dailySpend));
        }
        if (monthlySpend >= 100000) {
            spendScore = Math.min(28, spendScore + 12);
            reasons.add("Monthly spending spike: RM " + String.format("%.2f", monthlySpend));
        } else if (monthlySpend >= 50000) {
            spendScore = Math.min(28, spendScore + 8);
            reasons.add("High monthly spending: RM " + String.format("%.2f", monthlySpend));
        }
        if (yearlySpend >= 400000) {
            spendScore = Math.min(28, spendScore + 10);
            reasons.add("Yearly spending spike: RM " + String.format("%.2f", yearlySpend));
        } else if (yearlySpend >= 200000) {
            spendScore = Math.min(28, spendScore + 6);
            reasons.add("High yearly spending: RM " + String.format("%.2f", yearlySpend));
        }
        spendScore = Math.min(spendScore, 28);

        // 7. COMBINED
        if (amount >= 5000 && suspiciousLocation) {
            patternScore = Math.min(30, patternScore + 10);
            reasons.add("High amount + suspicious location combination");
        }
        if ("TRANSFER".equals(type) && suspiciousLocation && amount >= 3000) {
            patternScore = Math.min(30, patternScore + 8);
            reasons.add("Risky TRANSFER pattern (location + amount)");
        }

        // 8. ML mild
        double mlRaw = isolationForestService.score(transaction, count10, dailySpend);
        if (mlRaw >= 0) {
            if (mlRaw >= 0.72) {
                mlScore = 14;
                reasons.add("ML Isolation Forest: strong anomaly (score " + String.format("%.2f", mlRaw) + ")");
            } else if (mlRaw >= 0.62) {
                mlScore = 8;
                reasons.add("ML Isolation Forest: elevated anomaly (score " + String.format("%.2f", mlRaw) + ")");
            } else if (mlRaw >= 0.58) {
                mlScore = 4;
                reasons.add("ML Isolation Forest: mild deviation (score " + String.format("%.2f", mlRaw) + ")");
            }
        }

        int riskScore = velocityScore + amountScore + locationScore + timeScore
                + patternScore + spendScore + mlScore;
        if (riskScore > 100) riskScore = 100;

        boolean clearlyOrdinary =
                amount < 2000 && !suspiciousLocation && count10 < 3
                        && amountScore == 0 && locationScore == 0;
        if (clearlyOrdinary && riskScore >= 50 && velocityScore < 28) {
            riskScore = Math.min(riskScore, 42);
            reasons.add("Adjusted: ordinary local payment pattern");
        }

        String status = riskScore >= 50 ? "SUSPICIOUS" : "NORMAL";
        transaction.setRiskScore(riskScore);
        transaction.setStatus(status);
        transaction.setTimestamp(now);
        transaction.setReasons(reasons);
        return transactionRepository.save(transaction);
    }

    public List<Transaction> getAllTransactions() {
        return transactionRepository.findAll();
    }

    @Transactional
    public long clearAllTransactions() {
        long count = transactionRepository.count();
        transactionRepository.deleteAll();
        isolationForestService.reset();
        return count;
    }

    @Transactional
    public long clearAccountTransactions(String accountNumber) {
        if (accountNumber == null || accountNumber.isBlank()) return 0;
        List<Transaction> list = transactionRepository.findByAccountNumber(accountNumber.trim());
        long count = list.size();
        transactionRepository.deleteByAccountNumber(accountNumber.trim());
        return count;
    }

    public Transaction generateRandomTransaction() {
        String[] accountNumbers = {"1001", "1002", "1003", "1004", "1005", "2001", "2002", "3001", "4001"};
        String[] normalTypes = {"PAYMENT", "TRANSFER", "WITHDRAWAL", "PAYMENT", "PAYMENT"};
        String[] normalLocations = {
                "Kuala Lumpur", "Penang", "Johor Bahru", "Ipoh", "Melaka",
                "Shah Alam", "Klang", "Seremban", "Kota Kinabalu", "Kuching"
        };
        String[] riskyLocations = {"Overseas", "Unknown", "Foreign", "Offshore"};

        Transaction transaction = new Transaction();
        transaction.setAccountNumber(accountNumbers[(int) (Math.random() * accountNumbers.length)]);
        transaction.setTransactionType(normalTypes[(int) (Math.random() * normalTypes.length)]);

        boolean risky = Math.random() < 0.20;
        if (risky) {
            transaction.setAmount(Math.round((8000 + Math.random() * 17000) * 100.0) / 100.0);
            transaction.setLocation(riskyLocations[(int) (Math.random() * riskyLocations.length)]);
        } else {
            double normalAmount = 15 + Math.random() * 900;
            if (Math.random() < 0.15) normalAmount = 200 + Math.random() * 1500;
            transaction.setAmount(Math.round(normalAmount * 100.0) / 100.0);
            transaction.setLocation(normalLocations[(int) (Math.random() * normalLocations.length)]);
        }
        return checkTransaction(transaction);
    }

    public Transaction saveTransaction(Transaction transaction) {
        return transactionRepository.save(transaction);
    }
}