package com.ocsecure.game;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public final class ComputerPlayer {

    private final Random random = new Random();
    private final int[] secret;
    private List<int[]> candidates;

    public ComputerPlayer() {
        this.secret = generateRandomSecret();
        this.candidates = generateAllCandidates();
    }

    public int[] getSecret() {
        return secret.clone();
    }

    public int[] nextGuess() {
        return candidates.get(random.nextInt(candidates.size()));
    }

    public void applyFeedback(int[] guess, Judge.Result result) {
        List<int[]> filtered = new ArrayList<>();
        for (int[] candidate : candidates) {
            Judge.Result hypothetical = Judge.evaluate(candidate, guess);
            if (hypothetical.strike == result.strike && hypothetical.ball == result.ball) {
                filtered.add(candidate);
            }
        }
        if (!filtered.isEmpty()) {
            candidates = filtered;
        }
    }

    private int[] generateRandomSecret() {
        List<Integer> digits = new ArrayList<>();
        for (int i = 0; i <= 9; i++) {
            digits.add(i);
        }
        Collections.shuffle(digits, random);
        int[] result = new int[4];
        for (int i = 0; i < 4; i++) {
            result[i] = digits.get(i);
        }
        return result;
    }

    private List<int[]> generateAllCandidates() {
        List<int[]> all = new ArrayList<>();
        for (int a = 0; a <= 9; a++) {
            for (int b = 0; b <= 9; b++) {
                if (b == a) {
                    continue;
                }
                for (int c = 0; c <= 9; c++) {
                    if (c == a || c == b) {
                        continue;
                    }
                    for (int d = 0; d <= 9; d++) {
                        if (d == a || d == b || d == c) {
                            continue;
                        }
                        all.add(new int[]{a, b, c, d});
                    }
                }
            }
        }
        return all;
    }
}
