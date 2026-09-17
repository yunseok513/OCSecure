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
        System.out.println("0~9 중 중복 없는 숫자 4개로 비밀번호를 정합니다. 먼저 4 Strike를 맞추는 쪽이 승리합니다.\n");

        ComputerPlayer computer = new ComputerPlayer();
        int[] playerSecret = readDigitsLoop("당신의 비밀번호 4자리를 입력하세요 (예: 1234): ");

        System.out.println("\n비밀번호 설정이 완료되었습니다. 게임을 시작합니다!\n");

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
            Judge.Result computerResult = Judge.evaluate(playerSecret, computerGuess);
            System.out.println("[컴퓨터 추측] " + format(computerGuess) + " -> " + computerResult);
            if (computerResult.isPerfect()) {
                System.out.println("\n컴퓨터가 당신의 숫자를 맞췄습니다. 컴퓨터의 승리입니다!");
                break;
            }
            computer.applyFeedback(computerGuess, computerResult);

            round++;
        }

        scanner.close();
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
