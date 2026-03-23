import sys
from pathlib import Path

# 이 프로젝트를 최우선으로 잡게 강제
sys.path.insert(0, str(Path(__file__).parent))

from apps.api.main import app  # noqa: E402

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("run:app", host="127.0.0.1", port=8000, reload=True)