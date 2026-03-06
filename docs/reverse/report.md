# EndpointFileScanner.exe 방어적 리버스 분석 보고서


# 1. 개요

본 문서는 내가 빌드한 `EndpointFileScanner.exe`를 대상으로

정적 분석(PE/Imports/Strings)과 동적 분석(Procmon 관찰)을 통해

프로그램의 동작을 증거 기반(가설→관찰→결론)으로 재구성한다.



- 분석 관점: 엔드포인트 에이전트 관점(파일 I/O, 로그/리포트 생성, 스레드 사용 여부)

- 분석 범위: 악성 행위/우회 구현 없이 “관찰·진단” 중심



---



# 2. 분석 대상

- 파일명:   `EndpointFileScanner.exe`

- 빌드 구성:   Release x64 / (현재 빌드: v1.5.1)

- 경로:    `C:\Users\User\OneDrive\Desktop\C언어\(주)소만사 포트폴리오\src\EndpointFileScanner\x64\Release\EndpointFileScanner.exe`

- SHA256:   `e3e4645bf7491945f32f380bd19065792fcf05e4b6f504b9e98518cc2e23682a`

- 파일 크기: 120KB (122,880 바이트)

- 빌드 일시: ‎2026‎년 ‎3‎월 ‎1‎일 ‎일요일, ‏‎오후 11:41:12



---



# 3. 정적 분석



# 3.1 목적

실행 파일 내부 단서(Imports/Strings/PE 구조)를 통해

프로그램이 수행할 동작(디렉터리 순회, 파일 데이터 수집, 로그/CSV 저장, 스레드 사용 등)을 추정한다.



# 3.2 PE 구조 요약

- 머신/형식: x64(8664), PE32+(magic 20B) 실행 파일

- 섹션 구성: (.data / .pdata / .rdata / .reloc / .rsrc / .text)
  - .data: 전역/정적 데이터(Read/Write)
  - .pdata: 예외 처리/언와인드 정보(64-bit, Read Only)
  - .rdata: 읽기 전용 데이터/상수/문자열(Read Only)
  - .reloc: 재배치 정보(Discardable, Read Only)
  - .rsrc: 리소스(Read Only)
  - .text: 코드(Execute/Read)
- 엔트리포인트: 0x0000000140012E70 (mainCRTStartup)
- 서브시스템: Windows CUI(콘솔 프로그램)
- 보안/특성: ASLR(Dynamic base), NX compatible, High Entropy VA 활성화 표시

> 증거 파일:
- `evidence/reverse/static/Portable_Executable.txt`


# 3.3 Imports 요약

- 관찰(근거: `evidence/reverse/static/imports.txt`):

     - `KERNEL32.dll`에서 `CreateFileW`/`WriteConsoleW`/`FindFirstFileW`(계열) 등이 확인되어, 파일/디렉터리 접근과 콘솔 출력 사용이 드러남
     - `MultiByteToWideChar`/`WideCharToMultiByte`, `SetConsoleCP`/`SetConsoleOutputCP` 등으로 UTF-8<>UTF-16 변환 및 콘솔 인코딩 처리 흔적이 확인됨
     - `QueryPerformanceCounter`, `GetSystemTimeAsFileTime` 등으로 시간 측정/타임스탬프 처리 가능성이 보임
     - `MSVCP140.dll`, `VCRUNTIME140*.dll`, `api-ms-win-crt-*.dll` 의존으로 C++ 표준 라이브러리/런타임 사용이 확인됨
     - `_beginthreadex`, `_Thrd_join`, `_Mtx_lock`/`_Cnd_wait` 등으로 멀티스레드(워커풀) 및 동기화 사용 가능성이 나타남

- 해석:

      - “디렉터리 재귀 순회 > 파일 데이터 수집 > 콘솔 출력/로그 기록 > CSV 리포트 저장” 파이프라인과 일치하는 API 사용 흔적이 보임



> 증거 파일:

- `evidence/reverse/static/imports.txt`



# 3.4 Strings 요약

- 관찰:
  - `scanner.log` (실행 후 생성되는 로그 파일명)
  - `report.csv` (기본 리포트 파일명)
  - (콘솔 출력 문구) `스캔할 폴더 경로를 입력하시게나:` /`CSV 저장 경로를 입력하시게나:`
  - `--out` (CSV 저장 경로 옵션)
- 해석:
  - 실행 시 로그(scanner.log)와 CSV 리포트(report.csv)를 생성/기록하는 구조이며,
    입력>스캔>리포트 저장 흐름이 문자열 단서(파일명/콘솔 출력)로도 뒷받침된다.

> 증거 파일:
- `evidence/reverse/dynamic/scanner.log_screenshot.png`
- `evidence/reverse/dynamic/report.csv_screenshot.png`

---

# 4. 동적 분석


# 4.1 목적

정적 분석에서 세운 가설(파일 생성/쓰기 등)을 Procmon을 이용해 실제 실행 관찰로 검증



# 4.2 실행 환경

- OS: Windows 11

- 실행 명령/방법:`EndpointFileScanner.exe` 실행후 스캔경로 입력>엔터>저장할 경로입력부분에서 엔터(`report.csv`자동저장)




# 4.3 관찰 타임라인

-  `EndpointFileScanner.exe` 실행

-  `scanner.log` 생성/쓰기 확인

-  `report.csv` 생성/쓰기 확인

-  프로세스 종료



> 증거 파일:

- `evidence/reverse/dynamic/report.csv_screenshot.png` 
- `evidence/reverse/dynamic/scanner.log_screenshot.png`


---



# 5. 결론

관찰 결과를 종합하면 프로그램은 아래 파이프라인으로 동작한다.



1) 스캔 경로 입력

2) 디렉터리 재귀 순회

3) 파일 데이터 수집(크기/수정시간/확장자) 

4) 필터 적용(최대,최소크기/포함확장자/제외확장자)  

5) 로그 기록(scanner.log) 및 리포트 저장(report.csv)



---



# 6. 개선 아이디어

- 스킵 원인 분류
  - 관찰: 현재는 스킵을 `skipped` 단일 카운터로만 집계하며, 원인별 구분은 로그 메시지로만 확인 가능함
  - 개선: 스킵을 (1) 순회 중 오류 (2) 파일 데이터 수집 실패(file_size/last_write_time) (3) 파일/디렉터리 판정 실패 (4)필터 제외 로 분류하여 카운터와 요약 출력에 함께 반영
  - 효과: 무엇이 얼마나 누락됐는지를 원인별로 즉시 설명 가능하고 이슈 대응 속도가 향상됨

---



# 7. 간단한 재현 방법

1) 프로젝트 빌드(Release x64)

2) 실행:

- `EndpointFileScanner.exe` 실행후 스캔경로 입력>엔터>저장할 경로입력부분에서 엔터(`report.csv`자동저장)
- --out 옵션: "C:\스캔할 경로" --out "C:\저장하고싶은 경로\저장하고싶은 리포트 파일 이름.csv"

3) 정적 분석:

- Developer Command Prompt for VS 2022 실행:
  - `dumpbin /imports "<EndpointFileScanner.exe 전체 경로>" > evidence/reverse/static/imports.txt`

4) 동적 분석:

-Procmon 실행:
  - Procmon 필터(Include)
     - `Process Name is EndpointFileScanner.exe`
     - `scanner.log`, `report.csv` 생성/쓰기 확인
