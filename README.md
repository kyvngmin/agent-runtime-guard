# 자동 자막 파이프라인 설치 가이드

## 1. FFmpeg 설치
https://ffmpeg.org/download.html 에서 Windows 빌드 다운로드
→ 압축 해제 후 bin 폴더를 시스템 환경변수 PATH에 추가
→ 확인: 명령프롬프트에서 `ffmpeg -version`

## 2. Python 패키지 설치
```bash
pip install openai-whisper deep-translator watchdog
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
```
※ CUDA 버전 확인 후 cu121 → cu118 등으로 변경 가능
※ `nvidia-smi` 명령어로 CUDA 버전 확인

## 3. 설정 변경 (auto_subtitle.py 상단)
```python
INPUT_FOLDER  = r"C:\subtitle_input"   # 원본 영상 폴더
OUTPUT_FOLDER = r"C:\subtitle_output"  # 완성 영상 폴더
WHISPER_MODEL = "medium"               # medium 권장 (GPU 4GB 이상)
FONT_SIZE     = 20                     # 자막 크기 조절
```

## 4. 실행
```bash
python auto_subtitle.py
```

## 5. 사용법
- INPUT_FOLDER에 영상 파일(.mp4, .mkv, .avi 등) 복사
- 자동 감지 → STT → 번역 → 인코딩
- OUTPUT_FOLDER에 "_한국어자막.mp4" 파일 생성
- SRT 파일도 함께 저장됨 (나중에 수정 가능)

## 처리 속도 참고 (medium 모델, GPU 기준)
- 10분 영상 → 약 2~4분
- 30분 영상 → 약 6~12분

## 모델 크기별 정확도/속도
| 모델   | VRAM  | 속도  | 정확도 |
|--------|-------|-------|--------|
| tiny   | 1GB   | 매우빠름 | 보통  |
| base   | 1GB   | 빠름  | 보통   |
| small  | 2GB   | 보통  | 좋음   |
| medium | 5GB   | 보통  | 매우좋음 |
| large  | 10GB  | 느림  | 최고   |
