# Moodiary - 감정 일기장

휴가 중에도 간단하게 감정을 기록하고, 같은 감정을 공개하고 공감할 수 있는 감성 기록 웹 앱입니다.

---

## 💡 주요 기능

- 감정 일기 작성 (공개 / 비공개)
- 감정 일기 수정 / 삭제
- 댓글 기능 (작성 / 수정 / 삭제)
- 공감(좋아요) 기능
- 회원가입 / 로그인 / 로그아웃
- 마이페이지: 내가 쓴 감정 일기 목록 조회

---

## 📈 사용 기술

- **Backend**: Python, Flask  
- **Frontend**: HTML, CSS, Jinja2  
- **Database**: SQLite, SQLAlchemy  
- **관리**: Git, GitHub

---

## 🚀 실행 방법

```bash
git clone https://github.com/사용자명/moodiary.git
cd moodiary
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
flask run

---

## 📂 프로젝트 구조
moodiary.py          # Flask 메인 애플리케이션
templates/           # HTML 템플릿 폴더
static/css/          # CSS 스타일 시트
instance/site.db     # SQLite 데이터베이스
