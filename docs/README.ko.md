# Pabal

Go로 만든 작은 SMTP 중계·로컬 메일 테스트 서버입니다. 기본 `discard` 모드는 메일을 외부로 전송하지 않고 애플리케이션의 SMTP 동작을 확인합니다. `relay` 모드는 지정한 SMTP provider로 동기 전송합니다. 컨테이너 없이 하나의 바이너리로 실행할 수 있습니다.

IP 허용·차단, 발신자 제한, 수신 주소·도메인 허용·거부·폐기, 도메인별 provider 선택, TLS, 환경 변수 기반 인증, 웹 관리, 서버 별칭·분류·메모와 변경 이력을 지원합니다. 상세 설정과 실행 절차는 [영문 README](../README.md)를 따르세요. 예시는 localhost SMTP 12525, 내부 HTTP 관리 16882를 사용합니다.

```sh
go build -trimpath -o pabal .
go test -race ./...
go vet ./...
./pabal -config examples/discard.json -state-dir ./state
./pabal -help
```

먼저 `examples/discard.json`으로 로컬 수신 테스트를 하세요. Gmail·SES·SendGrid·일반 SMTP 예시는 실제 계정이나 비밀이 없는 자리표시자입니다. 비밀번호는 JSON에 넣지 않고 로컬 서비스 환경으로 전달합니다. OAuth2는 외부에서 얻은 access token을 사용하며 자동 발급·갱신하지 않습니다.

이 프로그램에는 내구성 있는 발송 큐와 재시도 worker가 없습니다. 전송 실패 시 발신 애플리케이션이 재시도해야 하며 한 SMTP transaction에 서로 다른 provider의 수신자를 섞으면 RCPT 단계에서 550으로 거부하므로 provider별로 별도 transaction을 보내고 수신자별 응답을 확인해야 합니다. upstream의 SMTP 수락을 최종 수신함 도착으로 표시하지 않습니다. 메일 본문과 인증 비밀은 저장하지 않으며 연결·envelope·결과만 기록합니다.

서버 구분은 출발지 IP 기준이므로 NAT·공유 IP에서는 여러 장비가 함께 보일 수 있습니다. runtime 상태, 세션 비밀, 전송 기록은 소스 저장소에 커밋하지 않습니다. 원본 코드에는 MIT 라이선스가 적용됩니다.

## 네이티브 서비스 설치

[systemd 예시](../deploy/pabal.service)는 전용 `pabal` 시스템 계정으로 실행합니다. 영문 README의 명령에 따라 바이너리를 `/usr/local/bin/pabal`, 기본 discard 설정을 `/etc/pabal/config.json`, 서비스 파일을 `/etc/systemd/system/pabal.service`에 설치합니다. 이미 계정이 있으면 재사용하세요. `systemctl daemon-reload` 후 `systemctl enable --now pabal.service`로 시작합니다.

systemd가 `/var/lib/pabal` 상태 디렉터리를 만들고 관리합니다. 기본 설정은 loopback이므로 LAN에서 쓰려면 리스너와 접근 정책을 조정합니다. relay 인증 환경 변수는 선택적인 로컬 `/etc/pabal/credentials.env`에 보관하며 소유자 root·권한 `0600`으로 제한합니다. discard 모드에는 인증 파일이 필요 없습니다. 인증 환경이나 시작 전용 설정 변경 뒤에는 서비스를 재시작합니다. 웹에서 저장한 정책은 재시작 후에도 유지되며 시작 설정의 대응 정책보다 우선합니다.

정책 변경은 기존 연결을 포함하여 다음 MAIL transaction부터 적용하며, 진행 중인 transaction은 기존 정책을 유지합니다. 클라이언트 표에서 IP 차단·해제 버튼이 상태에 따라 바뀝니다. 넓은 CIDR 차단은 개별 IP 해제로 제거하지 않고 설정 화면에서 관리합니다.
