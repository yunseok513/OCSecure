# OCSecure
Oracle Database 암복호와 모듈 개발 프로젝트

## 숫자 야구 게임

사람과 컴퓨터가 서로 상대의 4자리 비밀번호를 먼저 맞히는 콘솔 게임이 `src/main/java/com/ocsecure/game` 아래에 구현되어 있습니다. 0부터 9 사이의 중복 없는 숫자 네 개로 각자 비밀번호를 정한 뒤 번갈아 추측을 주고받으며, 자리와 숫자가 모두 일치하면 Strike로, 숫자는 있지만 자리가 다르면 Ball로 알려줍니다. 먼저 4 Strike를 받아내는 쪽이 승리하며, 컴퓨터는 지금까지 받은 힌트에 부합하는 후보만 남겨가며 다음 추측을 고르도록 만들어져 있습니다.

실행은 다음 명령으로 할 수 있습니다.

```
javac -d out src/main/java/com/ocsecure/game/*.java
java -cp out com.ocsecure.game.NumberBaseballGame
```
