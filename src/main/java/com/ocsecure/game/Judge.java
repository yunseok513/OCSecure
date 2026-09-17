package com.ocsecure.game;

public final class Judge {

    private Judge() {
    }

    public static Result evaluate(int[] secret, int[] guess) {
        int strike = 0;
        int ball = 0;
        for (int i = 0; i < secret.length; i++) {
            if (guess[i] == secret[i]) {
                strike++;
                continue;
            }
            for (int j = 0; j < secret.length; j++) {
                if (guess[i] == secret[j]) {
                    ball++;
                    break;
                }
            }
        }
        return new Result(strike, ball);
    }

    public static final class Result {
        public final int strike;
        public final int ball;

        public Result(int strike, int ball) {
            this.strike = strike;
            this.ball = ball;
        }

        public boolean isPerfect() {
            return strike == 4;
        }

        @Override
        public String toString() {
            return strike + " Strike, " + ball + " Ball";
        }
    }
}
