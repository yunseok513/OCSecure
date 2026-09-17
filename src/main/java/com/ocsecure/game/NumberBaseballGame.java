package com.ocsecure.game;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public final class NumberBaseballGame {

    public static void main(String[] args) {
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        new NumberBaseballGame().play();
    }

    private final Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);

    public void play() {
        System.out.println("=== 숫자 야구 게임 (사람 vs 컴퓨터) ===");
        System.out.println("0~9 중 중복 없는 숫자 4개로 당신만의 비밀번호를 마음속으로 정하세요.");
        System.out.println("이 프로그램에는 당신의 비밀번호를 입력하지 않습니다. 컴퓨터가 추측을 내놓으면 당신이 직접 Strike/Ball을 판정해서 알려주세요.");
        System.out.println("먼저 4 Strike를 받아내는 쪽이 승리합니다.\n");

        ComputerPlayer computer = new ComputerPlayer();

        int round = 1;
        while (true) {
            System.out.println("--- Round " + round + " ---");

            int[] playerGuess = readDigitsLoop("컴퓨터의 숫자를 추측해보세요: ");
            Judge.Result playerResult = Judge.evaluate(computer.getSecret(), playerGuess);
            System.out.println("[내 추측] " + format(playerGuess) + " -> " + playerResult);
            if (playerResult.isPerfect()) {
                System.out.println("\n축하합니다! 컴퓨터의 숫자를 맞췄습니다. 당신의 승리입니다!");
                break;
            }

            int[] computerGuess = computer.nextGuess();
            System.out.println("[컴퓨터 추측] " + format(computerGuess));
            Judge.Result computerResult = readJudgmentLoop();
            if (computerResult.isPerfect()) {
                System.out.println("\n컴퓨터가 당신의 숫자를 맞췄습니다. 컴퓨터의 승리입니다!");
                break;
            }
            computer.applyFeedback(computerGuess, computerResult);

            round++;
        }

        System.out.println("(컴퓨터의 비밀번호는 " + format(computer.getSecret()) + "였습니다.)");
        scanner.close();
    }

    private Judge.Result readJudgmentLoop() {
        while (true) {
            System.out.print("이 추측에 대한 결과를 'Strike Ball' 형식으로 입력하세요 (예: 2 1): ");
            String line = scanner.nextLine().trim();
            if (!line.matches("\\d\\s+\\d")) {
                System.out.println("숫자 두 개를 공백으로 구분해 입력해주세요 (예: 1 2).");
                continue;
            }
            String[] parts = line.split("\\s+");
            int strike = Integer.parseInt(parts[0]);
            int ball = Integer.parseInt(parts[1]);
            if (strike > 4 || ball > 4 || strike + ball > 4) {
                System.out.println("Strike와 Ball의 합은 4를 넘을 수 없습니다.");
                continue;
            }
            return new Judge.Result(strike, ball);
        }
    }

    private int[] readDigitsLoop(String prompt) {
        while (true) {
            System.out.print(prompt);
            int[] digits = readDigits();
            if (digits != null) {
                return digits;
            }
            System.out.println("0~9 사이의 서로 다른 숫자 4개를 입력해주세요.");
        }
    }

    private int[] readDigits() {
        String line = scanner.nextLine().trim();
        if (!line.matches("\\d{4}")) {
            return null;
        }
        int[] digits = new int[4];
        for (int i = 0; i < 4; i++) {
            digits[i] = line.charAt(i) - '0';
        }
        return hasDuplicate(digits) ? null : digits;
    }

    private boolean hasDuplicate(int[] digits) {
        for (int i = 0; i < digits.length; i++) {
            for (int j = i + 1; j < digits.length; j++) {
                if (digits[i] == digits[j]) {
                    return true;
                }
            }
        }
        return false;
    }

    private String format(int[] digits) {
        StringBuilder sb = new StringBuilder();
        for (int d : digits) {
            sb.append(d);
        }
        return sb.toString();
    }
}
