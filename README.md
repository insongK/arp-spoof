# ARP Spoofing Tool (Multi-Target)

이 도구는 여러 `sender-target` IP 쌍에 대해 동시에 ARP 스푸핑을 수행하고, 공격자가 패킷을 릴레이하는 기능을 수행합니다.

## 📦 기능 요약

- 인터페이스 선택 후 여러 sender/target 쌍을 입력하면,
- 각 쌍에 대해 ARP 감염을 지속적으로 수행하며,
- 공격자가 두 대상 사이에서 패킷을 가로채고 중계합니다.
- 사용자가 `Ctrl+C`로 종료할 때까지 동작합니다.


## 🛠️ 컴파일 방법

```bash
 $make
```

## 🚀 컴파일 방법
```bash
 sudo ./arp-spoof <interface> <sender_ip_1> <target_ip_1> [<sender_ip_2> <target_ip_2> ...]

```
