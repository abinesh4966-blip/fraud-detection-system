package com.FraudDetection.fraud_detection_system.service;

import com.FraudDetection.fraud_detection_system.model.Transaction;
import com.FraudDetection.fraud_detection_system.repository.TransactionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import smile.anomaly.IsolationForest;

import jakarta.annotation.PostConstruct;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
public class IsolationForestService {

    @Autowired
    private TransactionRepository transactionRepository;

    private IsolationForest model;
    private boolean ready = false;
    private int trainSize = 0;
    private LocalDateTime lastTrained;

    private static final int MIN_TRAIN = 12;

    @PostConstruct
    public void init() {
        // Do NOT auto-train on startup if old noisy data is a problem.
        // Model stays off until you explicitly retrain.
        ready = false;
        model = null;
        trainSize = 0;
        lastTrained = null;
        System.out.println("[ML] Isolation Forest is idle. Call /ml/retrain when ready.");
    }

    /** Wipe current model from memory (does not delete DB rows). */
    public synchronized void reset() {
        model = null;
        ready = false;
        trainSize = 0;
        lastTrained = null;
        System.out.println("[ML] Isolation Forest model cleared from memory.");
    }

    public synchronized boolean retrain() {
        List<Transaction> all = transactionRepository.findAll();
        List<double[]> rows = new ArrayList<>();

        // Train mainly on NORMAL / false-positive (treated as acceptable) behaviour
        for (Transaction t : all) {
            if (t.getAmount() == null) continue;
            if (t.getStatus() != null && "SUSPICIOUS".equalsIgnoreCase(t.getStatus()) && !t.isFalsePositive()) {
                continue;
            }
            rows.add(toFeatures(t, 0, 0));
        }

        // Fallback only if not enough NORMAL rows
        if (rows.size() < MIN_TRAIN) {
            rows.clear();
            for (Transaction t : all) {
                if (t.getAmount() == null) continue;
                rows.add(toFeatures(t, 0, 0));
            }
        }

        if (rows.size() < MIN_TRAIN) {
            reset();
            trainSize = rows.size();
            System.out.println("[ML] Not enough data to train (" + rows.size() + "/" + MIN_TRAIN + ")");
            return false;
        }

        double[][] data = rows.toArray(new double[0][]);
        model = IsolationForest.fit(data);
        ready = true;
        trainSize = rows.size();
        lastTrained = LocalDateTime.now();
        System.out.println("[ML] Isolation Forest trained on " + trainSize + " rows at " + lastTrained);
        return true;
    }

    public double score(Transaction tx, int velocity10, double dailySpendSoFar) {
        if (!ready || model == null) return -1;
        try {
            return model.score(toFeatures(tx, velocity10, dailySpendSoFar));
        } catch (Exception e) {
            return -1;
        }
    }

    public boolean isReady() {
        return ready;
    }

    public int getTrainSize() {
        return trainSize;
    }

    public LocalDateTime getLastTrained() {
        return lastTrained;
    }

    private double[] toFeatures(Transaction t, int velocity10, double dailySpendSoFar) {
        double amount = t.getAmount() != null ? t.getAmount() : 0;
        LocalDateTime ts = t.getTimestamp() != null ? t.getTimestamp() : LocalDateTime.now();

        double hour = ts.getHour() / 23.0;
        double dow = ts.getDayOfWeek().getValue() / 7.0;

        String type = t.getTransactionType() != null ? t.getTransactionType().toUpperCase(Locale.ROOT) : "";
        double typeCode;
        if ("TRANSFER".equals(type)) typeCode = 1.0;
        else if ("WITHDRAWAL".equals(type)) typeCode = 0.7;
        else if ("PAYMENT".equals(type)) typeCode = 0.4;
        else typeCode = 0.2;

        String loc = t.getLocation() != null ? t.getLocation().toLowerCase(Locale.ROOT) : "";
        double locRisk = (loc.contains("overseas") || loc.contains("foreign")
                || loc.contains("unknown") || loc.contains("offshore")
                || loc.contains("russia") || loc.contains("nigeria")
                || loc.contains("vpn") || loc.contains("dark")) ? 1.0 : 0.0;

        double vel = Math.min(velocity10, 10) / 10.0;
        double daily = Math.min(dailySpendSoFar + amount, 50000) / 50000.0;
        double logAmt = Math.log1p(Math.max(amount, 0)) / Math.log1p(25000);

        return new double[]{logAmt, hour, dow, typeCode, locRisk, vel, daily};
    }
}